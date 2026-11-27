/**
 * @name Value-proof rejection control
 * @kind problem
 * @problem.severity recommendation
 * @id pysec/value-proof-safety-probe
 */
import python
import semmle.python.dataflow.new.DataFlow
import ConstantChoice

from DataFlow::Node node
where constantChoice(node)
select node, "A native constant-value barrier was established here."
