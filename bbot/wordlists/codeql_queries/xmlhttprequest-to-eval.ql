/**
 * @name DOM-based XSS via dangerous eval of XMLHttpRequest responseText
 * @description Evaluating untrusted data from an XMLHttpRequest's responseText via eval() can lead to code injection.
 * @kind path-problem
 * @problem.severity error
 * @security.severity 9.5
 * @precision high
 * @id js/xhr-dynamic-eval-modified
 * @tags security
 * external/cwe/cwe-95
 */

 import javascript
 import DataFlow
 import DataFlow::PathGraph
 
 /**
  * Modified taint tracking configuration to catch cases where `this.responseText`
  * flows into an eval call even when used in string concatenation.
  */
 class XHRResponseToEvalConfigModified extends TaintTracking::Configuration {
   XHRResponseToEvalConfigModified() { this = "XHRResponseToEvalConfigModified" }
 
   override predicate isSource(DataFlow::Node source) {
     // Mark any property read of "responseText" as a taint source.
     exists(DataFlow::PropRead propRead |
       propRead = source and 
       propRead.getPropertyName() = "responseText"
     )
   }
 
   override predicate isSink(DataFlow::Node sink) {
     // Mark the argument of eval() as a taint sink.
     exists(CallExpr call |
       call.getCallee().(Identifier).getName() = "eval" and
       sink.asExpr() = call.getArgument(0)
     )
   }
   
   override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
     // Propagate taint through binary expressions (e.g. string concatenation).
     exists(BinaryExpr binop |
       // Check if the tainted value appears in either operand.
       (binop.getLeftOperand() = pred.asExpr() or binop.getRightOperand() = pred.asExpr()) and
       succ.asExpr() = binop
     )
   }
 }
 
 from XHRResponseToEvalConfigModified config, DataFlow::PathNode source, DataFlow::PathNode sink
 where config.hasFlowPath(source, sink)
 select sink.getNode(), source, sink, "Untrusted data from XMLHttpRequest.responseText flows to eval() after string concatenation.", source.getNode(), "XMLHttpRequest.responseText"
 