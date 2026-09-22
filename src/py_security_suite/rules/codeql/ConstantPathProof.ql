/**
 * @name Path flow excluded by constant choice
 * @description Native comparison of original and refined path flows.
 * @kind problem
 * @problem.severity recommendation
 * @id pysec/constant-path-proof
 */
import python
import ConstantChoice
import semmle.python.security.dataflow.PathInjectionQuery
module RefinedConfig implements DataFlow::StateConfigSig {
  class FlowState = PathInjectionConfig::FlowState;
  predicate isSource(DataFlow::Node n, FlowState s) { PathInjectionConfig::isSource(n, s) }
  predicate isSink(DataFlow::Node n, FlowState s) { PathInjectionConfig::isSink(n, s) }
  predicate isBarrier(DataFlow::Node n) { PathInjectionConfig::isBarrier(n) or constantChoice(n) }
  predicate isBarrier(DataFlow::Node n, FlowState s) { PathInjectionConfig::isBarrier(n, s) }
  predicate isAdditionalFlowStep(DataFlow::Node a, FlowState sa, DataFlow::Node b, FlowState sb) {
    PathInjectionConfig::isAdditionalFlowStep(a, sa, b, sb)
  }
  predicate observeDiffInformedIncrementalMode() { any() }
}
module RefinedFlow = TaintTracking::GlobalWithState<RefinedConfig>;
from DataFlow::Node sink
where exists(DataFlow::Node source | PathInjectionFlow::flow(source, sink)) and
  not exists(DataFlow::Node source, DataFlow::Node other |
    sameSinkCoordinates(other, sink) and RefinedFlow::flow(source, other))
select sink, "pysec-constant-choice-v1:py/path-injection"

