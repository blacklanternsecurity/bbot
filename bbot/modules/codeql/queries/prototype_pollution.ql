/**
 * @name Prototype Pollution via Recursive Merge
 * @description User-controlled data from URL sources flows into a recursive
 *              object merge/extend function that doesn't guard against
 *              __proto__, constructor, or prototype keys.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id bbot/prototype-pollution
 * @tags security
 *       external/cwe/cwe-915
 *       external/cwe/cwe-1321
 */

import javascript
import UrlSources

/**
 * A recursive function that assigns properties from one object to another
 * using a for-in loop without guarding dangerous keys.
 */
class UnsafeRecursiveMerge extends Function {
  UnsafeRecursiveMerge() {
    // Function contains a for-in loop
    exists(ForInStmt forin | forin.getParent+() = this.getBody()) and
    // Function contains a recursive call to itself
    exists(CallExpr call |
      call.getParent+() = this.getBody() and
      call.getCallee().(Identifier).getName() = this.getName()
    ) and
    // Function contains indexed property assignment (target[key] = ...)
    exists(Assignment assign |
      assign.getParent+() = this.getBody() and
      assign.getLhs() instanceof IndexExpr
    ) and
    // Does NOT guard against dangerous keys
    not exists(EqualityTest eq, StringLiteral str |
      eq.getParent+() = this.getBody() and
      str = eq.getAnOperand() and
      str.getValue() in ["__proto__", "constructor", "prototype"]
    ) and
    not exists(MethodCallExpr call |
      call.getParent+() = this.getBody() and
      call.getMethodName() = "hasOwnProperty"
    )
  }
}

module PrototypePollutionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isUrlSource(source) }

  predicate isSink(DataFlow::Node sink) {
    // Any argument to an unsafe recursive merge function
    exists(DataFlow::CallNode call, UnsafeRecursiveMerge fn |
      call.getACallee() = fn and
      sink = call.getAnArgument()
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    isUrlBarrier(node)
    or
    // JSON.parse is NOT a barrier (it's actually part of the attack chain)
    // but sanitization functions are
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "sanitize" and
      node = call
    )
    or
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["encodeURIComponent", "encodeURI"] and
      node = call
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // JSON.parse() propagates taint
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "parse" and
      pred = call.getArgument(0) and
      succ = call
    )
  }
}

module PrototypePollutionFlow = TaintTracking::Global<PrototypePollutionConfig>;
import PrototypePollutionFlow::PathGraph

from PrototypePollutionFlow::PathNode source, PrototypePollutionFlow::PathNode sink
where PrototypePollutionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Prototype pollution: user-controlled data from $@ flows to an unguarded recursive merge function.",
  source.getNode(), "URL source"
