/**
 * @name Untrusted XPath through library calls and local data containers
 * @description Tracks exact list elements and ConfigParser keys into XPath and elementpath expressions.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id pysec/collection-xpath-injection
 * @tags security
 *       external/cwe/cwe-643
 */
import python
import ConstantChoice
import CollectionValueFlow
import ConfigParserValueFlow
import QuotedXPath
import semmle.python.ApiGraphs
import semmle.python.security.dataflow.XpathInjectionQuery
module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof Source }
  predicate isSink(DataFlow::Node n) {
    n instanceof Sink
    or exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("elementpath").getMember(["select", "iter_select"]).getACall()
    | n in [call.getArg(1), call.getArgByName("path")])
  }
  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer or constantChoice(n) or quotedXPathHole(n) }
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    collectionValueFlowStep(a, b) or configParserValueFlowStep(a, b)
  }
}
module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph
from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink) and not exists(DataFlow::Node a, DataFlow::Node b |
  XpathInjectionFlow::flow(a, b) and sameSinkCoordinates(b, sink.getNode()))
select sink.getNode(), source, sink, "This XPath expression depends on $@ through local collection updates.", source.getNode(), "untrusted input"
