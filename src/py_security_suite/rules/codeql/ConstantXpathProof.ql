/**
 * @name XPath flow excluded by native constant or quoted-string proof
 * @description Native comparison of original and refined XPath flows.
 * @kind problem
 * @problem.severity recommendation
 * @id pysec/constant-xpath-proof
 */
import python
import ConstantChoice
import QuotedXPath
import semmle.python.security.dataflow.XpathInjectionQuery
module RefinedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof Source }
  predicate isSink(DataFlow::Node n) { n instanceof Sink }
  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer or constantChoice(n) or quotedXPathHole(n) }
  predicate observeDiffInformedIncrementalMode() { any() }
}
module RefinedFlow = TaintTracking::Global<RefinedConfig>;
from DataFlow::Node sink
where exists(DataFlow::Node source | XpathInjectionFlow::flow(source, sink)) and
  not exists(DataFlow::Node source, DataFlow::Node other |
    sameSinkCoordinates(other, sink) and RefinedFlow::flow(source, other))
select sink, "pysec-xpath-context-v2:py/xpath-injection"

