/**
 * @name PostMessage with Wildcard Origin
 * @description Calling postMessage with "*" as the target origin sends data to any
 *              listening frame, potentially leaking sensitive information.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @id bbot/postmessage-star
 * @tags security
 *       external/cwe/cwe-201
 */

import javascript

from DataFlow::MethodCallNode call
where
  call.getMethodName() = "postMessage" and
  call.getArgument(1).getStringValue() = "*"
select call, "postMessage() called with wildcard '*' origin, data may be leaked to untrusted frames."
