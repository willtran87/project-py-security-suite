/** Key-sensitive flow for direct ConfigParser set/get pairs in one statement block.
 * Distinct keys and later overwrites remain separate. Interpolation, subclasses,
 * dynamic keys and custom accessors are outside this model.
 */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow

private predicate sameKey(DataFlow::MethodCallNode a, DataFlow::MethodCallNode b) {
  a.getArg(0).asExpr().(StringLiteral).getText() = b.getArg(0).asExpr().(StringLiteral).getText() and
  a.getArg(1).asExpr().(StringLiteral).getText() = b.getArg(1).asExpr().(StringLiteral).getText()
}

predicate configParserValueFlowStep(DataFlow::Node source, DataFlow::Node sink) {
  exists(DataFlow::CallCfgNode parser, DataFlow::MethodCallNode write, DataFlow::MethodCallNode read,
         StmtList block, int first, int last |
    parser = API::moduleImport("configparser").getMember(["ConfigParser", "RawConfigParser"]).getACall() and
    write.getObject().getALocalSource() = parser and write.getMethodName() = "set" and
    read.getObject().getALocalSource() = parser and read.getMethodName() = "get" and sameKey(write, read) and
    source = write.getArg(2) and sink = read and
    block.getItem(first).(ExprStmt).getValue() = write.asExpr() and
    block.getItem(last).contains(read.asExpr()) and last in [first + 1 .. first + 16] and
    not exists(DataFlow::MethodCallNode other, int between |
      other.getObject().getALocalSource() = parser and other.getMethodName() = "set" and sameKey(write, other) and
      between in [first + 1 .. last] and block.getItem(between).contains(other.asExpr())) and
    not exists(DataFlow::AttrWrite override | override.getObject().getALocalSource() = parser)
  )
}
