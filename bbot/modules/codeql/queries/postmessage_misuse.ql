/**
 * @name PostMessage Security Issues
 * @description Detects two postMessage anti-patterns:
 *              1. Message handlers that don't check event.origin before using event.data in sinks
 *              2. postMessage() calls with "*" as the target origin, leaking data to any frame
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id bbot/postmessage-misuse
 * @tags security
 *       external/cwe/cwe-020
 *       external/cwe/cwe-201
 *       external/cwe/cwe-346
 */

import javascript

/**
 * A "message" event listener registration: addEventListener("message", handler)
 */
class MessageEventListener extends DataFlow::CallNode {
  Function handler;

  MessageEventListener() {
    this.getCalleeName() = "addEventListener" and
    this.getArgument(0).getStringValue() = "message" and
    handler = this.getArgument(1).asExpr().(Function)
  }

  Function getHandler() { result = handler }
}

/**
 * Holds if the handler function checks event.origin at some point.
 */
predicate handlerChecksOrigin(Function handler) {
  exists(PropAccess pa |
    pa.getPropertyName() = "origin" and
    pa.getEnclosingFunction() = handler
  )
}

/**
 * Holds if event.data flows to a dangerous sink inside the handler.
 */
predicate eventDataFlowsToSink(Function handler) {
  exists(PropAccess dataAccess, Expr sink |
    dataAccess.getPropertyName() = "data" and
    dataAccess.getEnclosingFunction() = handler and
    sink.getEnclosingFunction() = handler and
    (
      // innerHTML/outerHTML assignment
      exists(Assignment assign, PropAccess lhs |
        assign.getLhs() = lhs and
        lhs.getPropertyName() in ["innerHTML", "outerHTML"] and
        sink = assign.getRhs()
      )
      or
      // eval()
      exists(CallExpr call |
        call.getCallee().(Identifier).getName() = "eval" and
        sink = call.getArgument(0)
      )
      or
      // document.write
      exists(CallExpr call |
        call.getCallee().(PropAccess).getPropertyName() in ["write", "writeln"] and
        sink = call.getArgument(0)
      )
    )
  )
}

// Find message handlers without origin checks that use event.data in sinks
from MessageEventListener listener
where
  not handlerChecksOrigin(listener.getHandler()) and
  eventDataFlowsToSink(listener.getHandler())
select listener,
  "Message event handler does not check event.origin before using event.data in a dangerous sink."

// postMessage("*") calls are reported by postmessage_star.ql
