/**
 * @name Client-side URL Redirect
 * @description User-controlled data flows to URL redirect sinks (location.href,
 *              location.assign, location.replace, window.open), enabling open redirect attacks.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision high
 * @id bbot/client-side-redirect
 * @tags security
 *       external/cwe/cwe-601
 */

import javascript
import UrlSources

module ClientSideRedirectConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isUrlSource(source)
    or
    // where the visitor came from, which the attacker's page decides
    documentRead(source, "referrer")
  }

  predicate isSink(DataFlow::Node sink) {
    // location.href = ..., location = ...
    exists(DataFlow::PropWrite prop |
      prop.getPropertyName() in ["href", "location"] and
      sink = prop.getRhs()
    )
    or
    // location.assign(), location.replace()
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() in ["assign", "replace"] and
      sink = call.getArgument(0)
    )
    or
    // window.open()
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "open" and
      sink = call.getArgument(0)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    isUrlBarrier(node)
    or
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "startsWith" and
      node = call
    )
    or
    exists(DataFlow::NewNode n |
      n.getCalleeName() = "URL" and
      node = n
    )
  }
}

module ClientSideRedirectFlow = TaintTracking::Global<ClientSideRedirectConfig>;
import ClientSideRedirectFlow::PathGraph

from ClientSideRedirectFlow::PathNode source, ClientSideRedirectFlow::PathNode sink
where ClientSideRedirectFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Client-side redirect: user-controlled data from $@ flows to a URL redirect sink.",
  source.getNode(), "URL source"
