import python
import semmle.python.dataflow.new.DataFlow

/** A unique native local SSA definition; unknown and escaping bindings fail closed. */
private Expr localValue(Expr use) {
  exists(SsaVariable variable, Assign assignment |
    use instanceof Name and variable.getAUse().getNode() = use and
    variable.getVariable() instanceof FastLocalVariable and
    not variable.getVariable().escapes() and not variable.reachableWithoutDefinition() and
    not exists(variable.getAPhiInput()) and
    forall(SsaVariable other | other.getAUse().getNode() = use | other = variable) and
    variable.getDefinition().getNode() = assignment.getATarget()
  | result = assignment.getValue())
}

/** Bounded ASCII text avoids differences between Python and QL Unicode indexing. */
private string textValue(Expr expr, int depth) {
  depth in [0 .. 6] and result.length() <= 128 and
  (
    expr.(StringLiteral).isUnicode() and result = expr.(StringLiteral).getText() and
    result.regexpMatch("[ -~]*")
    or result = textValue(localValue(expr), depth + 1)
    or exists(Subscript read, string value, int index |
      expr = read and value = textValue(read.getObject(), depth + 1) and
      index = read.getIndex().(IntegerLiteral).getValue() and index >= 0 and index < value.length()
    | result = value.substring(index, index + 1))
  )
}

private string subjectValue(Pattern pattern) {
  exists(MatchStmt branch | pattern.getCase() = branch.getACase() |
    result = textValue(branch.getSubject(), 0))
}

private predicate cannotMatch(Pattern pattern) {
  exists(StringLiteral literal |
    literal = pattern.(MatchLiteralPattern).getLiteral() and literal.isUnicode() and
    literal.getText() != subjectValue(pattern)
  )
  or pattern instanceof MatchOrPattern and
    exists(pattern.(MatchOrPattern).getAPattern()) and
    forall(Pattern child | child = pattern.(MatchOrPattern).getAPattern() | cannotMatch(child))
}

predicate constantMatchChoice(DataFlow::Node node) {
  exists(MatchStmt branch, Case arm, Assign assignment, string value |
    arm = branch.getACase() and value = textValue(branch.getSubject(), 0) and
    cannotMatch(arm.getPattern()) and assignment = arm.getAStmt() and
    node.asExpr() = assignment.getValue()
  )
}

/** Only consecutive, discarded append(value)/pop(nonnegative-index) operations. */
private Call mutation(StmtList block, int start, int step, Name binding) {
  step in [1 .. 16] and
  result = block.getItem(start + step).(ExprStmt).getValue() and
  result.getFunc().(Attribute).getObject().(Name).getVariable() = binding.getVariable() and
  result.getFunc().(Attribute).getName() in ["append", "pop"] and
  exists(result.getPositionalArg(0)) and not exists(result.getPositionalArg(1)) and
  not exists(result.getANamedArg()) and not exists(result.getStarargs())
}

private int listLength(StmtList block, int start, Name binding, int step) {
  step in [0 .. 16] and result in [0 .. 16] and binding = block.getItem(start).(Assign).getATarget() and
  (
    step = 0 and result = 0
    or exists(Call call, int before |
      call = mutation(block, start, step, binding) and before = listLength(block, start, binding, step - 1)
    |
      call.getFunc().(Attribute).getName() = "append" and result = before + 1
      or call.getFunc().(Attribute).getName() = "pop" and
        call.getPositionalArg(0).(IntegerLiteral).getValue() in [0 .. before - 1] and result = before - 1
    )
  )
}

private Expr listItem(StmtList block, int start, Name binding, int step, int index) {
  step in [1 .. 16] and index in [0 .. listLength(block, start, binding, step) - 1] and
  exists(Call call, int before |
    call = mutation(block, start, step, binding) and before = listLength(block, start, binding, step - 1)
  |
    call.getFunc().(Attribute).getName() = "append" and
    (
      index = before and result = call.getPositionalArg(0)
      or index < before and result = listItem(block, start, binding, step - 1, index)
    )
    or call.getFunc().(Attribute).getName() = "pop" and
    (
      index < call.getPositionalArg(0).(IntegerLiteral).getValue() and
      result = listItem(block, start, binding, step - 1, index)
      or index >= call.getPositionalArg(0).(IntegerLiteral).getValue() and
      result = listItem(block, start, binding, step - 1, index + 1)
    )
  )
}

/** Prove a constant element only in a nonescaping, unaliased, closed local list sequence. */
predicate constantListRead(DataFlow::Node node) {
  exists(Assign init, Name binding, StmtList block, int start, int steps, Subscript read |
    steps in [1 .. 16] and block.getItem(start) = init and
    init.getValue() instanceof List and not exists(init.getValue().(List).getAnElt()) and
    binding = init.getATarget() and not exists(Name other | other = init.getATarget() and other != binding) and
    binding.getVariable() instanceof FastLocalVariable and not binding.getVariable().escapes() and
    node.asExpr() = read and read = block.getItem(start + steps + 1).(Assign).getValue() and
    read.getObject().(Name).getVariable() = binding.getVariable() and
    forall(Name occurrence | occurrence.getVariable() = binding.getVariable() |
      occurrence = binding
      or occurrence = read.getObject()
      or exists(int step | step in [1 .. steps] |
        occurrence = mutation(block, start, step, binding).getFunc().(Attribute).getObject())
    ) and
    exists(textValue(listItem(block, start, binding, steps, read.getIndex().(IntegerLiteral).getValue()), 0))
  )
}
