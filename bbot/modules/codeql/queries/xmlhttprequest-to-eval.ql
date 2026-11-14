/**
 * @name DOM-based XSS via dangerous eval of XMLHttpRequest responseText
 * @description Evaluating untrusted data from an XMLHttpRequest's responseText via eval()
 *              can lead to code injection.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.5
 * @precision high
 * @id bbot/xhr-dynamic-eval
 * @tags security
 *       external/cwe/cwe-095
 */

import javascript

module XHRResponseToEvalConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::PropRead propRead |
      propRead = source and
      propRead.getPropertyName() = "responseText"
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CallExpr call |
      call.getCallee().(Identifier).getName() = "eval" and
      sink.asExpr() = call.getArgument(0)
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(BinaryExpr binop |
      (binop.getLeftOperand() = pred.asExpr() or binop.getRightOperand() = pred.asExpr()) and
      succ.asExpr() = binop
    )
  }
}

module XHRResponseToEvalFlow = TaintTracking::Global<XHRResponseToEvalConfig>;
import XHRResponseToEvalFlow::PathGraph

from XHRResponseToEvalFlow::PathNode source, XHRResponseToEvalFlow::PathNode sink
where XHRResponseToEvalFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted data from $@ flows to eval() after string concatenation.",
  source.getNode(), "XMLHttpRequest.responseText"
