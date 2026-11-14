/**
 * @name Stored DOM-based Cross-Site Scripting (XSS)
 * @description Data from stored sources (localStorage, sessionStorage, cookies, postMessage)
 *              flows to dangerous DOM sinks. These require a separate injection vector to
 *              poison the stored data, making them lower confidence than direct URL-based DOM XSS.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision medium
 * @id bbot/dom-xss-stored
 * @tags security
 *       external/cwe/cwe-079
 */

import javascript

module StoredDomXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // localStorage.getItem() / sessionStorage.getItem()
    exists(DataFlow::MethodCallNode call |
      call = source and
      call.getMethodName() = "getItem" and
      (
        exists(DataFlow::PropRead storage |
          storage = call.getReceiver() and
          storage.getPropertyName() in ["localStorage", "sessionStorage"]
        )
        or
        call.getReceiver().asExpr().(GlobalVarAccess).getName() in ["localStorage", "sessionStorage"]
      )
    )
    or
    // localStorage[key] / sessionStorage[key] direct property access
    exists(DataFlow::PropRead prop |
      prop = source and
      (
        exists(DataFlow::PropRead storage |
          storage = prop.getBase() and
          storage.getPropertyName() in ["localStorage", "sessionStorage"]
        )
        or
        prop.getBase().asExpr().(GlobalVarAccess).getName() in ["localStorage", "sessionStorage"]
      )
    )
    or
    // document.cookie
    exists(DataFlow::PropRead prop |
      prop = source and
      prop.getPropertyName() = "cookie" and
      (
        exists(DataFlow::PropRead doc |
          doc = prop.getBase() and
          doc.getPropertyName() = "document"
        )
        or
        prop.getBase().asExpr().(GlobalVarAccess).getName() = "document"
      )
    )
    or
    // postMessage event.data
    exists(DataFlow::PropRead prop |
      prop = source and
      prop.getPropertyName() = "data" and
      exists(Function handler |
        prop.getEnclosingExpr().getEnclosingFunction() = handler and
        exists(DataFlow::CallNode addListener |
          addListener.getCalleeName() = "addEventListener" and
          addListener.getArgument(0).getStringValue() = "message" and
          addListener.getArgument(1).asExpr().(Function) = handler
        )
      )
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // element.innerHTML = ... / element.outerHTML = ...
    exists(DataFlow::PropWrite prop |
      prop.getPropertyName() in ["innerHTML", "outerHTML"] and
      sink = prop.getRhs()
    )
    or
    // document.write() / document.writeln()
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["write", "writeln"] and
      sink = call.getAnArgument()
    )
    or
    // jQuery .html(), .append(), .prepend(), .after(), .before(), .replaceWith()
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() in ["html", "append", "prepend", "after", "before", "replaceWith"] and
      sink = call.getArgument(0)
    )
    or
    // insertAdjacentHTML
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "insertAdjacentHTML" and
      sink = call.getArgument(1)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    // DOMPurify.sanitize()
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "sanitize" and
      node = call
    )
    or
    // encodeURIComponent / encodeURI
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["encodeURIComponent", "encodeURI"] and
      node = call
    )
    or
    // textContent / innerText assignments
    exists(DataFlow::PropWrite prop |
      prop.getPropertyName() in ["textContent", "innerText"] and
      node = prop.getRhs()
    )
  }
}

module StoredDomXssFlow = TaintTracking::Global<StoredDomXssConfig>;
import StoredDomXssFlow::PathGraph

from StoredDomXssFlow::PathNode source, StoredDomXssFlow::PathNode sink
where StoredDomXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Stored DOM XSS: data from $@ flows to a dangerous DOM sink (requires separate injection to poison stored data).",
  source.getNode(), "stored source"
