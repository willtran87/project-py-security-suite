/**
 * @name XPath flow excluded by constant choice
 * @description Native comparison of original and refined XPath flows.
 * @kind problem
 * @problem.severity recommendation
 * @id pysec/constant-xpath-proof
 */
import python
import ConstantChoice
import semmle.python.security.dataflow.XpathInjectionQuery
module RefinedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof Source }
  predicate isSink(DataFlow::Node n) { n instanceof Sink }
  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer or constantChoice(n) }
  predicate observeDiffInformedIncrementalMode() { any() }
}
module RefinedFlow = TaintTracking::Global<RefinedConfig>;
from DataFlow::Node sink
where exists(DataFlow::Node source | XpathInjectionFlow::flow(source, sink)) and
  not exists(DataFlow::Node source, DataFlow::Node other |
    sameSinkCoordinates(other, sink) and RefinedFlow::flow(source, other))
select sink, "pysec-constant-choice-v1:py/xpath-injection"

