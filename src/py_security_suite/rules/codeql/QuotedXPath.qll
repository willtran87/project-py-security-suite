/** A quote rejection applies only to the matching XPath string-literal hole.
 * The native guard model binds the checked SSA value and control-flow branch.
 * Other uses, formatting conversions and multi-hole expressions remain tainted.
 */
import python
import semmle.python.ApiGraphs
import semmle.python.frameworks.Flask
import semmle.python.dataflow.new.DataFlow

private predicate requestText(DataFlow::LocalSourceNode source) {
  exists(DataFlow::CallCfgNode call |
    source = call and
    call = Flask::request().getMember(["args", "form", "values", "headers", "cookies"]).getMember("get").getACall() and
    (not exists(call.getArg(1)) or call.getArg(1).asExpr() instanceof StringLiteral) and
    not exists(call.asExpr().(Call).getANamedArg()) and
    not exists(call.asExpr().(Call).getStarargs()) and not exists(call.asExpr().(Call).getKwargs()))
}

private predicate textOrigin(DataFlow::LocalSourceNode source) {
  source.asExpr() instanceof StringLiteral or requestText(source)
  or exists(DataFlow::CallCfgNode call |
    source = call and call = API::moduleImport("urllib.parse").getMember(["unquote", "unquote_plus"]).getACall() and
    exists(call.getArg(0).getALocalSource()) and
    forall(DataFlow::LocalSourceNode input | input = call.getArg(0).getALocalSource() |
      requestText(input) or input.asExpr() instanceof StringLiteral))
  or exists(DataFlow::MethodCallNode call |
    source = call and call.getMethodName() = "decode" and
    call.getObject().getALocalSource() = API::moduleImport("base64").getMember(["b64decode", "urlsafe_b64decode"]).getACall())
}

private predicate rejectsApostrophe(DataFlow::GuardNode guard, ControlFlowNode value, boolean branch) {
  exists(CompareNode compare, ControlFlowNode quote |
    compare = guard and quote.getNode().(StringLiteral).getText() = "'" and
    (
      compare.operands(quote, any(In op), value) and branch = false
      or compare.operands(quote, any(NotIn op), value) and branch = true
    )
  )
}

predicate quotedXPathHole(DataFlow::Node node) {
  exists(DataFlow::ExprNode checked, Fstring expression, Name hole, StringLiteral prefix, StringLiteral suffix,
         Location before, Location value, Location after |
    checked = DataFlow::BarrierGuard<rejectsApostrophe/3>::getABarrierNode() and
    node.asExpr() = expression and
    count(expression.getAValue()) = 3 and
    prefix = expression.getValue(0) and hole = expression.getValue(1) and suffix = expression.getValue(2) and
    hole = checked.asExpr() and exists(checked.getALocalSource()) and
    forall(DataFlow::LocalSourceNode source | source = checked.getALocalSource() | textOrigin(source)) and
    before = prefix.getLocation() and value = hole.getLocation() and after = suffix.getLocation() and
    before.getEndLine() = value.getStartLine() and value.getEndLine() = after.getStartLine() and
    before.getEndColumn() + 1 = value.getStartColumn() and value.getEndColumn() + 1 = after.getStartColumn() and
    prefix.getText().regexpMatch("/[A-Za-z_][A-Za-z0-9_/-]*\\[@[A-Za-z_][A-Za-z0-9_.:-]*='") and
    suffix.getText() = "']"
  )
}
