/**
 * @name Environment credential reaches a log across call boundaries
 * @description A credential-bearing environment value flows to logging or printing.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id pysec/environment-secret-to-log
 * @tags security
 *       external/cwe/cwe-532
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.CleartextLoggingCustomizations

module EnvironmentSecretConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallCfgNode call |
      (
        call = API::moduleImport("os").getMember("getenv").getACall() or
        call = API::moduleImport("os").getMember("environ").getMember("get").getACall() or
        call = API::moduleImport("os").getMember("environ").getMember("__getitem__").getACall()
      ) and
      call.getArg(0).asExpr().(StringLiteral).getText().regexpMatch(
        "(?i).*(password|passwd|secret|token|api.?key|private.?key|credential|database.?url|dsn).*"
      ) and
      source = call
    )
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof CleartextLogging::Sink }
}

module EnvironmentSecretFlow = TaintTracking::Global<EnvironmentSecretConfig>;
import EnvironmentSecretFlow::PathGraph

from EnvironmentSecretFlow::PathNode source, EnvironmentSecretFlow::PathNode sink
where EnvironmentSecretFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "An environment credential from $@ reaches this log.",
  source.getNode(), "this source"
