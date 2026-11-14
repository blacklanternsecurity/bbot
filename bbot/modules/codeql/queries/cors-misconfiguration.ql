/**
 * @name CORS origin reflected from the request
 * @description Server code sends the request's Origin back in Access-Control-Allow-Origin, so any site can read the
 *              response, with the user's cookies if credentials are allowed.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 5.3
 * @precision high
 * @id bbot/cors-misconfiguration
 * @tags security
 *       external/cwe/cwe-942
 */

import javascript

/** Holds if `node` reads the request's Origin header. */
predicate requestOrigin(DataFlow::Node node) {
  exists(DataFlow::PropRead read | read = node |
    read.getPropertyName().toLowerCase() = "origin" and
    read.getBase().(DataFlow::PropRead).getPropertyName() = "headers"
  )
  or
  exists(DataFlow::MethodCallNode call | call = node |
    call.getMethodName() = ["get", "header", "getHeader"] and
    call.getArgument(0).getStringValue().toLowerCase() = "origin"
  )
}

/** Holds if `node` is the value of an Access-Control-Allow-Origin header the code sets. */
predicate allowedOrigin(DataFlow::Node node) {
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = ["setHeader", "header", "set", "append"] and
    call.getArgument(0).getStringValue().toLowerCase() = "access-control-allow-origin" and
    node = call.getArgument(1)
    or
    // an object of headers: res.set({...}), res.writeHead(200, {...})
    call.getMethodName() = ["set", "header", "writeHead"] and
    exists(DataFlow::PropWrite header |
      header = call.getAnArgument().getALocalSource().(DataFlow::ObjectLiteralNode).getAPropertyWrite() and
      header.getPropertyName().toLowerCase() = "access-control-allow-origin" and
      node = header.getRhs()
    )
  )
}

module ReflectedOriginConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { requestOrigin(node) }

  predicate isSink(DataFlow::Node node) { allowedOrigin(node) }
}

module ReflectedOriginFlow = TaintTracking::Global<ReflectedOriginConfig>;

from DataFlow::Node source, DataFlow::Node sink
where ReflectedOriginFlow::flow(source, sink)
select sink, "Access-Control-Allow-Origin is set to $@.", source, "the request's Origin header"
