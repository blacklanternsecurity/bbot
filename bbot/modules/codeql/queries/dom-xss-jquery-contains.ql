/**
 * @name DOM-based XSS via potentially dangerous jQuery selectors
 * @description Untrusted input like location.hash used in potentially dangerous jQuery selectors
 *              (such as :contains, has(), or other non-ID selectors) can lead to XSS when jQuery
 *              processes the selector.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id bbot/dom-xss-jquery-unsafe-selectors
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript

module HashToJQueryContainsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::PropRead hashProp |
      hashProp = source and
      hashProp.getPropertyName() = "hash" and
      (
        exists(DataFlow::PropRead locationProp |
          locationProp = hashProp.getBase() and
          locationProp.getPropertyName() = "location"
        )
        or
        hashProp.getBase().asExpr().(GlobalVarAccess).getName() = "location"
      )
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode jqueryCall |
      (jqueryCall.getCalleeName() = "$" or jqueryCall.getCalleeName() = "jQuery") and
      sink = jqueryCall.getArgument(0) and
      (
        exists(string val | val = sink.getStringValue() and val.indexOf(":contains(") >= 0) or
        exists(Expr expr |
          expr = sink.asExpr() and
          (expr instanceof BinaryExpr or expr instanceof AddExpr) and
          not isSafeIdSelector(expr)
        )
      )
    )
    or
    exists(DataFlow::MethodCallNode hasCall |
      hasCall.getMethodName() = "has" and
      sink = hasCall.getArgument(0) and
      not isSafeSelector(hasCall.getArgument(0))
    )
  }
}

private predicate isSafeIdSelector(Expr expr) {
  exists(AddExpr addExpr, StringLiteral hashChar |
    addExpr = expr and
    hashChar = addExpr.getLeftOperand() and
    hashChar.getValue() = "#"
  )
  or
  exists(StringLiteral strLit |
    strLit = expr and
    strLit.getValue().charAt(0) = "#"
  )
}

private predicate isSafeSelector(DataFlow::Node node) {
  exists(StringLiteral strLit |
    strLit = node.asExpr() and
    strLit.getValue().charAt(0) = "#"
  )
  or
  exists(AddExpr addExpr, StringLiteral hashChar |
    addExpr = node.asExpr() and
    hashChar = addExpr.getLeftOperand() and
    hashChar.getValue() = "#"
  )
}

module HashToJQueryContainsFlow = TaintTracking::Global<HashToJQueryContainsConfig>;
import HashToJQueryContainsFlow::PathGraph

from HashToJQueryContainsFlow::PathNode source, HashToJQueryContainsFlow::PathNode sink
where HashToJQueryContainsFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "The value from $@ is used unsafely in a jQuery selector, potentially leading to DOM XSS.",
  source.getNode(), "location.hash"
