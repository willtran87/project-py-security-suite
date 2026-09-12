/**
 * @name Request data crosses into server session state
 * @description Tracks untrusted request data into Flask session keys or values requiring a trust decision.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id pysec/session-trust-boundary
 * @tags security
 *       external/cwe/cwe-501
 */
import python
import semmle.python.ApiGraphs
import semmle.python.frameworks.Flask
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import ConstantChoice
import CollectionValueFlow
import ConfigParserValueFlow

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    n = Flask::request().getMember(["args", "form", "values", "headers", "cookies"]).asSource()
  }
  predicate isSink(DataFlow::Node n) {
    exists(Assign write, Subscript target |
      target = write.getATarget() and
      target.getObject() = API::moduleImport("flask").getMember("session").getAValueReachableFromSource().asExpr() and
      n.asExpr() in [target.getIndex(), write.getValue()]
    )
  }
  predicate isBarrier(DataFlow::Node n) { constantChoice(n) or constantSelectedMatchRead(n) }
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    collectionValueFlowStep(a, b) or configParserValueFlowStep(a, b)
  }
}
module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph
from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Review the trust decision before storing $@ in session state.", source.getNode(), "untrusted request data"
