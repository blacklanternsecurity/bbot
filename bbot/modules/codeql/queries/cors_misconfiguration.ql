/**
 * @name CORS Misconfiguration for Credentials
 * @description Server-side code that reflects the request Origin header in
 *              Access-Control-Allow-Origin enables cross-origin data theft.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id bbot/cors-misconfiguration
 * @tags security
 *       external/cwe/cwe-346
 *       external/cwe/cwe-942
 */

import javascript

// A call that sets the ACAO header to a reflected request value, like:
//   res.setHeader("Access-Control-Allow-Origin", req.headers.origin)
//   res.set("Access-Control-Allow-Origin", req.headers.origin)
from DataFlow::MethodCallNode call, DataFlow::PropRead reqProp
where
  call.getMethodName() in ["setHeader", "set", "header", "writeHead"] and
  call.getArgument(0).getStringValue().toLowerCase() = "access-control-allow-origin" and
  reqProp.getPropertyName() in ["origin", "referer", "host"] and
  reqProp.flowsTo(call.getArgument(1))
select call,
  "Access-Control-Allow-Origin header is set to a reflected request value (" +
  reqProp.getPropertyName() + "), which may enable CORS-based attacks."
