/**
 * @name XSS via Exception Messages
 * @description Exception messages containing user-controlled data that are rendered
 *              into the DOM can lead to cross-site scripting.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.0
 * @precision medium
 * @id bbot/exception-xss
 * @tags security
 *       external/cwe/cwe-079
 */

import javascript

module ExceptionXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Catch clause parameter
    exists(CatchClause cc |
      source.asExpr() = cc.getAChildExpr()
    )
    or
    // .catch() callback parameter
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "catch" and
      source = call.getCallback(0).getParameter(0)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::PropWrite prop |
      prop.getPropertyName() in ["innerHTML", "outerHTML"] and
      sink = prop.getRhs()
    )
    or
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["write", "writeln"] and
      sink = call.getAnArgument()
    )
    or
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "html" and
      sink = call.getArgument(0)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["sanitize", "encodeURIComponent", "encodeURI"] and
      node = call
    )
    or
    exists(DataFlow::PropWrite prop |
      prop.getPropertyName() in ["textContent", "innerText"] and
      node = prop.getRhs()
    )
  }
}

module ExceptionXssFlow = TaintTracking::Global<ExceptionXssConfig>;
import ExceptionXssFlow::PathGraph

from ExceptionXssFlow::PathNode source, ExceptionXssFlow::PathNode sink
where ExceptionXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Exception message from $@ flows to a DOM sink, potentially enabling XSS.",
  source.getNode(), "exception"
