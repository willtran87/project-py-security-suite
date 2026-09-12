/**
 * @name Untrusted path selected from a mutated local list
 * @description Tracks exact elements through supported local list updates into filesystem operations.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id pysec/collection-path-injection
 * @tags security
 *       external/cwe/cwe-022
 */
import python
import ConstantChoice
import CollectionValueFlow
import ConfigParserValueFlow
import semmle.python.security.dataflow.PathInjectionQuery
module Config implements DataFlow::StateConfigSig {
  class FlowState = PathInjectionConfig::FlowState;
  predicate isSource(DataFlow::Node n, FlowState s) { PathInjectionConfig::isSource(n, s) }
  predicate isSink(DataFlow::Node n, FlowState s) { PathInjectionConfig::isSink(n, s) }
  predicate isBarrier(DataFlow::Node n) { PathInjectionConfig::isBarrier(n) or constantChoice(n) }
  predicate isBarrier(DataFlow::Node n, FlowState s) { PathInjectionConfig::isBarrier(n, s) }
  predicate isAdditionalFlowStep(DataFlow::Node a, FlowState sa, DataFlow::Node b, FlowState sb) {
    PathInjectionConfig::isAdditionalFlowStep(a, sa, b, sb)
    or sa = sb and collectionValueFlowStep(a, b)
    or sa = sb and configParserValueFlowStep(a, b)
  }
}
module Flow = TaintTracking::GlobalWithState<Config>;
import Flow::PathGraph
from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink) and not exists(DataFlow::Node a, DataFlow::Node b |
  PathInjectionFlow::flow(a, b) and sameSinkCoordinates(b, sink.getNode()))
select sink.getNode(), source, sink, "This path depends on $@ through local collection updates.", source.getNode(), "untrusted input"
