/**
 * @name DOM text written back as HTML
 * @description Text the page reads from the document, such as a field's value, is written back into the page as
 *              HTML, so markup that was inert as text runs.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 3.5
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

  predicate isBarrier(DataFlow::Node node) {
    htmlBarrier(node)
    or
    // text from the document is a string, or a list of them, whose length is a number
    node.(DataFlow::PropRead).getPropertyName() = "length"
    or
    sharedCode(node)
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    iterationStep(node1, node2)
  }
}

module DomTextFlow = TaintTracking::Global<DomTextConfig>;

from DataFlow::Node source, DataFlow::Node sink
where DomTextFlow::flow(source, sink)
select sink, "$@ is written back into the page as HTML.", source, "Text read from the document"
