/**
 * @name Untrusted HTML returned by a dynamic Flask registration hook
 * @description Tracks request collection data into HTML string responses from dynamic Flask registration hooks.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id pysec/flask-registration-html-injection
 * @tags security
 *       external/cwe/cwe-079
 */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.frameworks.Flask
import semmle.python.security.dataflow.ReflectedXSSCustomizations
import semmle.python.security.dataflow.ReflectedXssQuery
import ConstantChoice
import NativeValueFacts
import HtmlValueFacts
import CollectionValueFlow
import ConfigParserValueFlow

/** Resolve the actual import call feeding the hook receiver. Literal imports must
 * match the defining module. Unknown dynamic names retain medium-precision coverage.
 */
private predicate registration(Function setup) {
  setup.getScope() instanceof Module and not setup.isAsync() and not setup.isGenerator() and
  not exists(setup.getADecorator()) and
  forall(Name definition | definition.getVariable() = setup.getArg(0).(Name).getVariable() and
    (definition.isDefinition() or definition.isDeletion()) | definition = setup.getArg(0)) and
  forall(Function other | other.getScope() = setup.getScope() and other.getName() = setup.getName() | other = setup) and
  forall(Name definition | definition.getVariable().getScope() = setup.getScope() and
    definition.getId() = setup.getName() and (definition.isDefinition() or definition.isDeletion()) |
    definition = setup.getDefinition().getParent().(Assign).getATarget()) and
  exists(API::CallNode imported, DataFlow::CallCfgNode call, DataFlow::AttrRead member, DataFlow::Node name |
    imported = API::moduleImport("importlib").getMember("import_module").getACall() and
    name in [imported.getArg(0), imported.getArgByName("name")] and
    member = call.getFunction().getALocalSource() and member.getAttributeName() = setup.getName() and
    imported = member.getObject().getALocalSource() and
    (
      exists(StringLiteral literal | literal = name.getALocalSource().asExpr() |
        literal.getText() = setup.getScope().(Module).getName())
      or not exists(StringLiteral literal | literal = name.getALocalSource().asExpr())
    ) and
    not exists(DataFlow::AttrWrite write |
      imported = write.getObject().getALocalSource() and
      (write.getAttributeName() = setup.getName() or write.unknownAttribute())) and
    call.getArg(0) = Flask::FlaskApp::instance().getAValueReachableFromSource()
  )
}
private predicate htmlReturn(DataFlow::Node sink) {
  exists(Function handler, Function setup, Call decorator, Attribute method, Name receiver, Return ret, Name value, Assign init |
    registration(setup) and handler.getScope() = setup and
    decorator = handler.getADecorator() and count(handler.getADecorator()) = 1 and method = decorator.getFunc() and
    method.getName() in ["route", "get", "post"] and
    decorator.getPositionalArg(0) instanceof StringLiteral and
    receiver = method.getObject() and receiver.getVariable() = setup.getArg(0).(Name).getVariable() and
    ret.getScope() = handler and value = ret.getValue() and sink.asExpr() = value and
    value.getVariable() instanceof FastLocalVariable and not value.getVariable().escapes() and
    init.getScope() = handler and init.getValue() instanceof StringLiteral and
    init.getATarget().(Name).getVariable() = value.getVariable() and
    forall(Name def | def.getVariable() = value.getVariable() and def.isDefinition() |
      def = init.getATarget() or exists(AugAssign update | update.getTarget() = def and update.getOperation().getOp() instanceof Add)
    )
  )
}
module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node = Flask::request().getMember(["args", "form", "values", "headers", "cookies"]).asSource() }
  predicate isSink(DataFlow::Node node) { htmlReturn(node) }
  predicate isAdditionalFlowStep(DataFlow::Node source, DataFlow::Node sink) {
    markupIdentityEscapeStep(source, sink)
    or collectionValueFlowStep(source, sink)
    or configParserValueFlowStep(source, sink)
  }
  predicate isBarrier(DataFlow::Node node) {
    htmlValueBarrier(node) or constantChoice(node) or constantSelectedMatchRead(node)
  }
}
module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph
from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink) and not exists(DataFlow::Node oldSource, DataFlow::Node oldSink |
  ReflectedXssFlow::flow(oldSource, oldSink) and sameSinkCoordinates(oldSink, sink.getNode()))
select sink.getNode(), source, sink, "This string response contains $@.", source.getNode(), "untrusted input"
