import python
import NativeValueFacts
import semmle.python.dataflow.new.DataFlow

/** A bounded, pure integer evaluator using native local SSA bindings. */
private int number(Expr expr, int depth) {
  depth in [0 .. 6] and result in [-10000 .. 10000] and
  (
    result = expr.(IntegerLiteral).getValue()
    or
    exists(BinaryExpr op, int left, int right |
      expr = op and left = number(op.getLeft(), depth + 1) and
      right = number(op.getRight(), depth + 1)
    |
      op.getOp() instanceof Add and result = left + right
      or op.getOp() instanceof Sub and result = left - right
      or op.getOp() instanceof Mult and result = left * right
    )
    or
    exists(SsaVariable variable, Assign assignment |
      expr instanceof Name and variable.getAUse().getNode() = expr and
      variable.getVariable() instanceof FastLocalVariable and
      not variable.getVariable().escapes() and
      not variable.reachableWithoutDefinition() and
      not exists(variable.getAPhiInput()) and
      forall(SsaVariable other | other.getAUse().getNode() = expr | other = variable) and
      variable.getDefinition().getNode() = assignment.getATarget() and
      result = number(assignment.getValue(), depth + 1)
    )
  )
}

private boolean conditionValue(Expr expr) {
  expr instanceof True and result = true
  or expr instanceof False and result = false
  or
  exists(Compare comparison, int left, int right |
    expr = comparison and not exists(comparison.getComparator(1)) and
    left = number(comparison.getLeft(), 0) and
    right = number(comparison.getComparator(0), 0)
  |
    (comparison.getOp(0) instanceof Gt or comparison.getOp(0) instanceof GtE or
     comparison.getOp(0) instanceof Lt or comparison.getOp(0) instanceof LtE or
     comparison.getOp(0) instanceof Eq or comparison.getOp(0) instanceof NotEq) and
    if (
      comparison.getOp(0) instanceof Gt and left > right
      or comparison.getOp(0) instanceof GtE and left >= right
      or comparison.getOp(0) instanceof Lt and left < right
      or comparison.getOp(0) instanceof LtE and left <= right
      or comparison.getOp(0) instanceof Eq and left = right
      or comparison.getOp(0) instanceof NotEq and left != right
    ) then result = true else result = false
  )
}

predicate constantChoice(DataFlow::Node node) {
  constantMatchChoice(node) or constantListRead(node)
  or
  exists(IfExp choice |
    node.asExpr() = choice and
    (
      conditionValue(choice.getTest()) = true and choice.getBody() instanceof StringLiteral
      or conditionValue(choice.getTest()) = false and choice.getOrelse() instanceof StringLiteral
    )
  )
  or
  // Clear only the RHS occurrence of a direct assignment in a branch whose
  // pure condition is proved unreachable. Other uses of the value stay live.
  exists(If branch, Assign assignment |
    node.asExpr() = assignment.getValue() and
    (
      conditionValue(branch.getTest()) = false and assignment = branch.getAStmt()
      or conditionValue(branch.getTest()) = true and assignment = branch.getAnOrelse()
    )
  )
}

/** Include every native node sharing the emitted SARIF sink coordinates. */
predicate sameSinkCoordinates(DataFlow::Node first, DataFlow::Node second) {
  exists(Location a, Location b |
    a = first.getLocation() and b = second.getLocation() and
    a.getFile() = b.getFile() and
    a.getStartLine() = b.getStartLine() and a.getStartColumn() = b.getStartColumn() and
    a.getEndLine() = b.getEndLine() and a.getEndColumn() = b.getEndColumn()
  )
}



