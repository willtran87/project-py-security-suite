/** Exact element flow through bounded straight-line local list operations.
 * Unknown calls, indexes and control flow terminate the model. This adds
 * positive flow evidence; it never supplies a proof for suppressing a finding.
 */
import python
import semmle.python.dataflow.new.DataFlow

private predicate alias(Name use, Name root, StmtList block, int start, int step) {
  root = block.getItem(start).(Assign).getATarget() and step in [0 .. 16] and
  (
    use.getVariable() = root.getVariable() and
    not exists(Name write, int pos |
      pos in [start + 1 .. start + step] and block.getItem(pos).contains(write) and
      write.getVariable() = root.getVariable() and (write.isDefinition() or write.isDeletion()))
    or exists(Assign assignment, Name target, int before |
      before in [1 .. step] and block.getItem(start + before) = assignment and
      assignment.getATarget() = target and use.getVariable() = target.getVariable() and
      alias(assignment.getValue().(Name), root, block, start, before - 1) and
      not exists(Name write, int pos |
        pos in [start + before + 1 .. start + step] and block.getItem(pos).contains(write) and
        write.getVariable() = target.getVariable() and (write.isDefinition() or write.isDeletion()))
    )
  )
}

private Stmt operation(StmtList block, int start, int step) {
  step in [1 .. 16] and
  (
    result = block.getItem(start + step)
    or exists(FunctionDef definition, Function f, Call call, int before |
      before in [1 .. step - 1] and block.getItem(start + before) = definition and
      f = definition.getDefinedFunction() and not f.isAsync() and not f.isGenerator() and
      not exists(f.getADecorator()) and not exists(f.getAnArg()) and count(f.getAStmt()) = 1 and
      call = block.getItem(start + step).(ExprStmt).getValue() and
      call.getFunc().(Name).getVariable() = definition.getATarget().(Name).getVariable() and
      not exists(call.getAnArg()) and
      not exists(Name write, int pos |
        pos in [start + before + 1 .. start + step] and block.getItem(pos).contains(write) and
        write.getVariable() = definition.getATarget().(Name).getVariable() and
        (write.isDefinition() or write.isDeletion()))
    | result = f.getAStmt())
  )
}

private Call callAt(StmtList block, int start, Name root, int step, string method) {
  result = operation(block, start, step).(ExprStmt).getValue() and
  alias(result.getFunc().(Attribute).getObject().(Name), root, block, start, step - 1) and
  result.getFunc().(Attribute).getName() = method and
  not exists(result.getANamedArg()) and not exists(result.getStarargs())
}

private predicate unchanged(StmtList block, int start, Name root, int step) {
  root = block.getItem(start).(Assign).getATarget() and step in [1 .. 16] and (
  exists(Assign assignment |
    assignment = block.getItem(start + step) and
    alias(assignment.getValue().(Name), root, block, start, step - 1) and
    assignment.getATarget() instanceof Name
  )
  or block.getItem(start + step) instanceof FunctionDef
  )
}

private int lengthAt(StmtList block, int start, Name root, int step) {
  root = block.getItem(start).(Assign).getATarget() and
  step in [0 .. 16] and result in [0 .. 16] and
  (
    step = 0 and result = count(block.getItem(start).(Assign).getValue().(List).getAnElt())
    or exists(int previous |
      previous = lengthAt(block, start, root, step - 1)
    |
      unchanged(block, start, root, step) and result = previous
      or exists(Assign write, Subscript target |
        write = operation(block, start, step) and target = write.getATarget() and
        alias(target.getObject().(Name), root, block, start, step - 1) and
        target.getIndex().(IntegerLiteral).getValue() in [0 .. previous - 1]
      | result = previous)
      or exists(Call call | call = callAt(block, start, root, step, "append") and
        exists(call.getPositionalArg(0)) and not exists(call.getPositionalArg(1)) | result = previous + 1)
      or exists(Call call | call = callAt(block, start, root, step, "insert") and
        call.getPositionalArg(0).(IntegerLiteral).getValue() in [0 .. previous] and
        exists(call.getPositionalArg(1)) and not exists(call.getPositionalArg(2)) | result = previous + 1)
      or exists(Call call, List values | call = callAt(block, start, root, step, "extend") and
        values = call.getPositionalArg(0) and not exists(call.getPositionalArg(1)) |
        result = previous + count(values.getAnElt()))
      or exists(Call call | call = callAt(block, start, root, step, "pop") and
        call.getPositionalArg(0).(IntegerLiteral).getValue() in [0 .. previous - 1] and
        not exists(call.getPositionalArg(1)) | result = previous - 1)
    )
  )
}

private Expr itemAt(StmtList block, int start, Name root, int step, int index) {
  step in [0 .. 16] and index in [0 .. lengthAt(block, start, root, step) - 1] and
  (
    step = 0 and result = block.getItem(start).(Assign).getValue().(List).getElt(index)
    or exists(int previous |
      previous = lengthAt(block, start, root, step - 1)
    |
      unchanged(block, start, root, step) and result = itemAt(block, start, root, step - 1, index)
      or exists(Assign write, Subscript target, int changed |
        write = operation(block, start, step) and target = write.getATarget() and
        alias(target.getObject().(Name), root, block, start, step - 1) and
        changed = target.getIndex().(IntegerLiteral).getValue() and changed in [0 .. previous - 1]
      | if index = changed then result = write.getValue()
        else result = itemAt(block, start, root, step - 1, index))
      or exists(Call call | call = callAt(block, start, root, step, "append") |
        if index = previous then result = call.getPositionalArg(0)
        else result = itemAt(block, start, root, step - 1, index))
      or exists(Call call, int inserted |
        call = callAt(block, start, root, step, "insert") and
        inserted = call.getPositionalArg(0).(IntegerLiteral).getValue()
      | index = inserted and result = call.getPositionalArg(1)
        or index < inserted and result = itemAt(block, start, root, step - 1, index)
        or index > inserted and result = itemAt(block, start, root, step - 1, index - 1))
      or exists(Call call | call = callAt(block, start, root, step, "extend") |
        if index >= previous then result = call.getPositionalArg(0).(List).getElt(index - previous)
        else result = itemAt(block, start, root, step - 1, index))
      or exists(Call call, int removed | call = callAt(block, start, root, step, "pop") and
        removed = call.getPositionalArg(0).(IntegerLiteral).getValue() |
        if index < removed then result = itemAt(block, start, root, step - 1, index)
        else result = itemAt(block, start, root, step - 1, index + 1))
    )
  )
}

predicate collectionValueFlowStep(DataFlow::Node source, DataFlow::Node sink) {
  exists(StmtList block, int start, int steps, Assign init, Name root, Subscript read |
    block.getItem(start) = init and root = init.getATarget() and init.getValue() instanceof List and
    count(init.getATarget()) = 1 and steps in [1 .. 16] and
    block.getItem(start + steps + 1).contains(read) and read.getScope() = init.getScope() and
    alias(read.getObject().(Name), root, block, start, steps) and
    source.asExpr() = itemAt(block, start, root, steps, read.getIndex().(IntegerLiteral).getValue()) and
    sink.asExpr() = read
  )
}
