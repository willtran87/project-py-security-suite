/** Bounded text provenance for context-specific string proofs.
 * Unknown objects, escaping locals and unsupported mutations fail closed.
 * Nullable request getters qualify only where the string operation succeeds.
 */
import python
import semmle.python.ApiGraphs
import semmle.python.frameworks.Flask
import semmle.python.dataflow.new.DataFlow

private predicate plainCall(Call call) {
  not exists(call.getANamedArg()) and not exists(call.getStarargs()) and
  not exists(call.getKwargs())
}

private predicate requestGetter(DataFlow::CallCfgNode call) {
  call = Flask::request().getMember(["args", "form", "values", "headers", "cookies"]).getMember("get").getACall() and
  (not exists(call.getArg(1)) or call.getArg(1).asExpr() instanceof StringLiteral) and
  not exists(call.getArg(2)) and plainCall(call.asExpr())
}

/** A locally held request getlist result with no writes, escapes or method calls. */
private predicate requestListRead(Subscript read) {
  exists(Name binding, SsaVariable variable, Assign assignment, DataFlow::CallCfgNode call |
    read.getObject() = binding and read.getIndex() instanceof IntegerLiteral and
    variable.getAUse().getNode() = binding and
    variable.getVariable() instanceof FastLocalVariable and not variable.getVariable().escapes() and
    not variable.reachableWithoutDefinition() and not exists(variable.getAPhiInput()) and
    forall(SsaVariable other | other.getAUse().getNode() = binding | other = variable) and
    variable.getDefinition().getNode() = assignment.getATarget() and
    assignment.getValue() = call.asExpr() and
    call = Flask::request().getMember(["args", "form", "values", "headers"]).getMember("getlist").getACall() and
    not exists(call.getArg(1)) and plainCall(call.asExpr()) and
    forall(Name use | use.getVariable() = binding.getVariable() and not use.isDefinition() |
      not use.isDeletion() and
      (exists(If test | test.getTest() = use) or
       exists(Subscript item | item.getObject() = use and item.getIndex() instanceof IntegerLiteral and
         item.getCtx() instanceof Load)))
  )
}

predicate knownText(Expr expr, int depth) {
  depth in [0 .. 12] and
  (
    expr.(StringLiteral).isUnicode() or expr instanceof Fstring
    or exists(DataFlow::CallCfgNode call | expr = call.asExpr() and requestGetter(call))
    or expr instanceof Attribute and
      expr = Flask::request().getMember("path").getAValueReachableFromSource().asExpr()
    or exists(Name use, SsaVariable variable |
      expr = use and variable.getAUse().getNode() = use and
      variable.getVariable() instanceof FastLocalVariable and not variable.getVariable().escapes() and
      // An undefined fast local raises UnboundLocalError, rather than falling
      // back to a global object. Every successful load must use one of these
      // definitions; all of them must produce text.
      forall(SsaVariable other | other.getAUse().getNode() = use | other = variable) and
      exists(variable.getAnUltimateDefinition()) and
      forall(SsaVariable definition | definition = variable.getAnUltimateDefinition() |
        exists(Assign assignment | definition.getDefinition().getNode() = assignment.getATarget() and
          knownText(assignment.getValue(), depth + 1)))
    )
    or exists(Subscript read | expr = read and
      (requestListRead(read) or knownText(read.getObject(), depth + 1)))
    or exists(BinaryExpr add | expr = add and add.getOp() instanceof Add and
      knownText(add.getLeft(), depth + 1) and knownText(add.getRight(), depth + 1))
    or exists(IfExp choice | expr = choice and
      knownText(choice.getBody(), depth + 1) and knownText(choice.getOrelse(), depth + 1))
    or exists(DataFlow::CallCfgNode call |
      expr = call.asExpr() and
      call = API::moduleImport("urllib").getMember("parse").getMember(["unquote", "unquote_plus"]).getACall() and
      knownText(call.getArg(0).asExpr(), depth + 1))
    or exists(DataFlow::MethodCallNode call |
      expr = call.asExpr() and call.getMethodName() = "decode" and
      exists(call.getObject().getALocalSource()) and
      forall(DataFlow::LocalSourceNode source | source = call.getObject().getALocalSource() |
        source = API::moduleImport("base64").getMember(["b64decode", "urlsafe_b64decode"]).getACall() or
        source.asExpr() instanceof Attribute and
        source = Flask::request().getMember("query_string").getAValueReachableFromSource()))
  )
}
