/**
 * @name Client-side Code Injection via eval-like functions
 * @description User-controlled data flows to eval(), Function(), setTimeout(string),
 *              or setInterval(string), enabling arbitrary code execution.
 *              Only tracks sources that are directly exploitable via a crafted URL.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id bbot/eval-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 */

import javascript
import UrlSources

module EvalInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isUrlSource(source) }

  predicate isSink(DataFlow::Node sink) {
    // eval()
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "eval" and
      sink = call.getArgument(0)
    )
    or
    // new Function(...)
    exists(DataFlow::NewNode call |
      call.getCalleeName() = "Function" and
      sink = call.getAnArgument()
    )
    or
    // setTimeout / setInterval with string argument (not function references)
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["setTimeout", "setInterval"] and
      sink = call.getArgument(0) and
      // Exclude function expressions/arrows
      not sink.asExpr() instanceof Function and
      // Exclude simple identifier references (variable names pointing to functions)
      not sink.asExpr() instanceof VarAccess and
      // Exclude property accesses like obj.method
      not sink.asExpr() instanceof PropAccess
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Propagate taint through string concatenation
    exists(BinaryExpr binop |
      (binop.getLeftOperand() = pred.asExpr() or binop.getRightOperand() = pred.asExpr()) and
      succ.asExpr() = binop
    )
  }
}

module EvalInjectionFlow = TaintTracking::Global<EvalInjectionConfig>;
import EvalInjectionFlow::PathGraph

from EvalInjectionFlow::PathNode source, EvalInjectionFlow::PathNode sink
where EvalInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Code injection: user-controlled data from $@ flows to a code execution sink.",
  source.getNode(), "tainted source"
