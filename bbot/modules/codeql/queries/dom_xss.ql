/**
 * @name DOM-based Cross-Site Scripting (XSS)
 * @description User-controlled data from URL sources flows to dangerous DOM sinks
 *              (innerHTML, outerHTML, document.write, jQuery .html()/.append()) without sanitization.
 *              Only tracks sources that are directly exploitable via a crafted URL — stored sources
 *              (localStorage, cookies) are excluded as they require a separate injection vector.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id bbot/dom-xss
 * @tags security
 *       external/cwe/cwe-079
 */

import javascript
import UrlSources

module DomXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isUrlSource(source) }

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
    isUrlBarrier(node)
    or
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
    // textContent / innerText assignments (safe sinks, not XSS vectors)
    exists(DataFlow::PropWrite prop |
      prop.getPropertyName() in ["textContent", "innerText"] and
      node = prop.getRhs()
    )
  }
}

module DomXssFlow = TaintTracking::Global<DomXssConfig>;
import DomXssFlow::PathGraph

from DomXssFlow::PathNode source, DomXssFlow::PathNode sink
where DomXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "DOM XSS: user-controlled data from $@ flows to a dangerous DOM sink.",
  source.getNode(), "URL source"
