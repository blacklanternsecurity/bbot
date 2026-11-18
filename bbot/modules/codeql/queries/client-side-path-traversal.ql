/**
 * @name Client-side path traversal to XSS
 * @description Input an attacker controls picks the path of a request the page makes, and the response is written
 *              into the page as HTML or run as code. With ../ the input reaches any path on that host, so any response
 *              there carrying the attacker's text, like an endpoint that echoes a parameter, runs in the page.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision medium
 * @id bbot/client-side-path-traversal
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-022
 */

import javascript
import Inputs
import Sinks
import Barriers

/**
 * An XMLHttpRequest, followed out of the function that makes it. CodeQL's own model only sees one opened and read
 * where it's made, not one made by a helper like `function makeRequest() { return new XMLHttpRequest(); }`.
 */
class Xhr extends DataFlow::NewNode {
  Xhr() { this = DataFlow::globalVarRef("XMLHttpRequest").getAnInstantiation() }

  private DataFlow::SourceNode track(DataFlow::TypeTracker t) {
    t.start() and result = this
    or
    exists(DataFlow::TypeTracker t2 | result = this.track(t2).track(t2, t))
  }

  private DataFlow::SourceNode object() { result = this.track(DataFlow::TypeTracker::end()) }

  /** Gets a reference to it, including `this` in its event handlers. */
  DataFlow::SourceNode ref() {
    result = this.object()
    or
    exists(DataFlow::FunctionNode handler | result = handler.getReceiver() |
      handler = this.object().getAPropertyWrite(any(string name | name.matches("on%"))).getRhs().getAFunctionValue()
      or
      handler = this.object().getAMethodCall("addEventListener").getArgument(1).getAFunctionValue()
    )
  }

  DataFlow::Node url() { result = this.ref().getAMethodCall("open").getArgument(1) }

  DataFlow::Node response() { result = this.ref().getAPropertyRead(["response", "responseText", "responseXML"]) }
}

/** Holds if the page requests `url`, and `response` is what comes back. */
predicate request(DataFlow::Node url, DataFlow::Node response) {
  exists(ClientRequest request | url = request.getUrl() and response = request.getAResponseDataNode())
  or
  exists(Xhr xhr | url = xhr.url() and response = xhr.response())
}

/** Holds if the page writes what comes back from `url` into itself as HTML: jQuery's $(...).load(url). */
predicate loadsHtml(DataFlow::Node url) {
  url = JQuery::objectRef().getAMethodCall("load").getArgument(0) and
  not url.getALocalSource() instanceof DataFlow::FunctionNode
}

/** Climbing out of the path the page meant, with ../, needs the attacker to choose where their text starts. */
predicate requestPath(DataFlow::Node node, InputState state) {
  (request(node, _) or loadsHtml(node)) and state.controlsStart()
}

/** Text in the query or fragment, encoded with its slashes, or a number can't change the path. */
predicate pathBarrier(DataFlow::Node node) {
  afterPath(node) or
  numeric(node) or
  node = DataFlow::globalVarRef(["encodeURIComponent", "escape"]).getACall()
}

module PathFlow = InputFlow<requestPath/2, pathBarrier/1>;

module HtmlResponseConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { request(_, node) }

  predicate isSink(DataFlow::Node node) { htmlSink(node) }

  predicate isBarrier(DataFlow::Node node) { htmlBarrier(node) or sharedCode(node) }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) { iterationStep(node1, node2) }
}

module HtmlResponseFlow = TaintTracking::Global<HtmlResponseConfig>;

module CodeResponseConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { request(_, node) }

  predicate isSink(DataFlow::Node node) { codeSink(node) }

  predicate isBarrier(DataFlow::Node node) { codeBarrier(node) or sharedCode(node) }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) { iterationStep(node1, node2) }
}

module CodeResponseFlow = TaintTracking::Global<CodeResponseConfig>;

from DataFlow::Node source, DataFlow::Node url, DataFlow::Node sink, string what
where
  PathFlow::flow(source, url) and
  // a page fetching its own path, the way pjax-style navigation does, gets what the server would have sent anyway
  not pathInput(source) and
  (
    exists(DataFlow::Node response | request(url, response) |
      HtmlResponseFlow::flow(response, sink) and what = "written into the page as HTML"
      or
      CodeResponseFlow::flow(response, sink) and what = "run as code"
    )
    or
    loadsHtml(url) and sink = url and what = "written into the page as HTML"
  )
select sink, "Text from $@ picks the path of a request whose response is " + what + ".", source,
  inputName(source)
