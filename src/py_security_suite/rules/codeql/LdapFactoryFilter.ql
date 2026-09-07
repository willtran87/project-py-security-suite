/**
 * @name Untrusted data reaches an LDAP filter through an imported connection factory
 * @description Tracks source-verified imported connection factories and untrusted search-filter data.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id pysec/ldap-factory-filter-injection
 * @tags security
 *       external/cwe/cwe-090
 */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.LdapInjectionCustomizations
import semmle.python.security.dataflow.LdapInjectionQuery
import semmle.python.Concepts
import ConstantChoice

private DataFlow::TypeTrackingNode constructed(DataFlow::TypeTracker tracker) {
  tracker.start() and result = API::moduleImport("ldap3").getMember("Connection").getACall()
  or exists(DataFlow::TypeTracker previous | result = constructed(previous).track(previous, tracker))
}
private DataFlow::Node constructed() { constructed(DataFlow::TypeTracker::end()).flowsTo(result) }

private predicate connectionFactory(Function factory, Module mod) {
  factory.getScope() = mod and not factory.isAsync() and not factory.isGenerator() and
  not exists(factory.getADecorator()) and
  exists(Return ret | ret.getScope() = factory) and
  forall(Return ret | ret.getScope() = factory |
    exists(DataFlow::Node value | value = constructed() and value.asExpr() = ret.getValue())
  ) and
  forall(Function other | other.getScope() = mod and other.getName() = factory.getName() | other = factory) and
  forall(Name binding |
    binding.getVariable().getScope() = mod and binding.getId() = factory.getName() and
    (binding.isDefinition() or binding.isDeletion())
  | binding = factory.getDefinition().getParent().(Assign).getATarget())
}
/** Track native import identities through global references and local aliases. */
private DataFlow::TypeTrackingNode imported(string qualified, DataFlow::TypeTracker tracker) {
  exists(Function factory, Module mod, string name |
    connectionFactory(factory, mod) and name = mod.getName() + "." + factory.getName() and
    (qualified = name or name.matches(qualified + ".%"))
  ) and
  (
    tracker.start() and
    (
      qualified = result.asExpr().(ImportExpr).getImportedModuleName()
      or qualified = result.asExpr().(ImportMember).getImportedModuleName()
    )
    or exists(DataFlow::TypeTracker previous |
      result = imported(qualified, previous).track(previous, tracker))
  )
}
private string importedName(DataFlow::Node node, int depth) {
  depth in [0 .. 8] and
  (
    imported(result, DataFlow::TypeTracker::end()).flowsTo(node)
    or exists(DataFlow::AttrRead attribute |
      attribute = node.getALocalSource()
    | result = importedName(attribute.getObject(), depth + 1) + "." + attribute.getAttributeName())
  )
}
private DataFlow::Node factoryResult() {
  exists(Function factory, Module mod, DataFlow::CallCfgNode call |
    connectionFactory(factory, mod) and
    not exists(DataFlow::AttrWrite write |
      importedName(write.getObject(), 0) = mod.getName() and
      (write.getAttributeName() = factory.getName() or write.unknownAttribute())
    ) and
    importedName(call.getFunction(), 0) = mod.getName() + "." + factory.getName()
  | result = call)
}
private DataFlow::TypeTrackingNode connection(DataFlow::TypeTracker tracker) {
  tracker.start() and result = factoryResult()
  or exists(DataFlow::TypeTracker previous | result = connection(previous).track(previous, tracker))
}
private DataFlow::Node connection() { connection(DataFlow::TypeTracker::end()).flowsTo(result) }
module FilterConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof LdapInjection::Source

  }
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.calls(connection(), "search") and
      sink in [call.getArg(1), call.getArgByName("search_filter")]
    )
  }
  predicate isAdditionalFlowStep(DataFlow::Node source, DataFlow::Node sink) {
    // DN escaping does not make a value safe in the filter argument.
    exists(LdapDnEscaping escaping |
      source = escaping.getAnInput() and sink = escaping.getOutput())
  }
  predicate isBarrier(DataFlow::Node node) {
    node instanceof LdapInjection::FilterSanitizer or constantChoice(node)
  }
}
module FilterFlow = TaintTracking::Global<FilterConfig>;
import FilterFlow::PathGraph
from FilterFlow::PathNode source, FilterFlow::PathNode sink
where FilterFlow::flowPath(source, sink) and
  not exists(DataFlow::Node originalSource, DataFlow::Node originalSink |
    LdapInjectionFilterFlow::flow(originalSource, originalSink) and
    sameSinkCoordinates(originalSink, sink.getNode()))
select sink.getNode(), source, sink, "LDAP filter depends on $@ through a tracked ldap3 connection.", source.getNode(), "this untrusted source"
