/**
 * @name DOM text written back as HTML
 * @description Text the page reads from the document, such as a field's value, is written back into the page as
 *              HTML, so markup that was inert as text runs.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision medium
 * @id bbot/dom-text-xss
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript
import Inputs
import Sinks
import Barriers

/** Holds if `node` reads text from the document, which is inert until it's parsed as HTML again. */
predicate domText(DataFlow::Node node) {
  node = domElement().getAPropertyRead(["value", "textContent", "innerText"])
  or
  exists(JQuery::MethodCall call | call = node |
    call.getMethodName() = ["val", "text"] and
    call.getNumArgument() = 0
  )
}

module DomTextConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { domText(node) }

  predicate isSink(DataFlow::Node node) { htmlSink(node) }

  predicate isBarrier(DataFlow::Node node) { htmlBarrier(node) }
}

module DomTextFlow = TaintTracking::Global<DomTextConfig>;

from DataFlow::Node source, DataFlow::Node sink
where DomTextFlow::flow(source, sink)
select sink, "$@ is written back into the page as HTML.", source, "Text read from the document"
