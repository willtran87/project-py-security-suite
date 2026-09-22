import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.frameworks.MarkupSafe
import semmle.python.security.dataflow.ReflectedXSSCustomizations

private DataFlow::CallCfgNode markupEscape() {
  result = API::moduleImport("markupsafe").getMember(["escape", "escape_silent"]).getACall()
  or result = API::moduleImport("flask").getMember("escape").getACall()
  or result = MarkupSafeModel::Markup::classRef().getMember("escape").getACall()
}

/** MarkupSafe returns an existing Markup value without escaping it again. */
predicate markupIdentityEscapeStep(DataFlow::Node source, DataFlow::Node sink) {
  exists(DataFlow::CallCfgNode call |
    call = markupEscape() and source = call.getArg(0) and
    source = MarkupSafeModel::Markup::instance() and sink = call
  )
}
private predicate markupOperation(DataFlow::Node node) {
  node instanceof MarkupSafeModel::Markup::StringConcat
  or node instanceof MarkupSafeModel::Markup::StringFormat
  or node instanceof MarkupSafeModel::Markup::PercentStringFormat
  or node = markupEscape()
}
private DataFlow::Node markupOperand(DataFlow::Node output) {
  result = MarkupSafeModel::Markup::instance() and
  (
    result.asExpr() in [output.asExpr().(BinaryExpr).getLeft(), output.asExpr().(BinaryExpr).getRight()]
    or result.asExpr() = output.asExpr().(BinaryExpr).getRight().(Tuple).getAnElt()
    or result = output.(DataFlow::MethodCallNode).getObject()
    or result in [output.(DataFlow::CallCfgNode).getArg(_), output.(DataFlow::CallCfgNode).getArgByName(_)]
  )
}
private DataFlow::TypeTrackingNode safeMarkup(DataFlow::TypeTracker tracker, int depth) {
  depth in [0 .. 6] and
  (
    tracker.start() and
    (
      exists(DataFlow::CallCfgNode call |
        call = MarkupSafeModel::Markup::classRef().getACall() and
        call.getArg(0).asExpr() instanceof StringLiteral
      | result = call)
      or exists(HtmlEscaping escaping |
        result = escaping.getOutput() and
        (not markupOperation(result) or forall(DataFlow::Node operand | operand = markupOperand(result) |
          safeMarkup(DataFlow::TypeTracker::end(), depth + 1).flowsTo(operand)))
      )
    )
    or exists(DataFlow::TypeTracker previous | result = safeMarkup(previous, depth).track(previous, tracker))
  )
}

/** Escaping one operand must not clear taint already trusted as unsafe Markup. */
predicate htmlValueBarrier(DataFlow::Node node) {
  node instanceof ReflectedXss::ConstCompareAsSanitizerGuard
  or exists(HtmlEscaping escaping |
    node = escaping.getOutput() and
    (not markupOperation(node) or forall(DataFlow::Node operand | operand = markupOperand(node) |
      safeMarkup(DataFlow::TypeTracker::end(), 0).flowsTo(operand)))
  )
}
