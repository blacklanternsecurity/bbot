/**
 * @name DOM-based cross-site scripting
 * @description Input an attacker controls is written into the page as HTML, or becomes the URL of a link, form or
 *              frame, where a javascript: URL runs as code.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id bbot/dom-xss
 * @tags security
 *       external/cwe/cwe-079
 */

import javascript
import Inputs
import Sinks
import Barriers

/** Markup needs <, so only decoded input can write it. */
predicate html(DataFlow::Node node, InputState state) { htmlSink(node) and state.isDecoded() }

/** A javascript: URL needs the attacker to choose the start of the URL. */
predicate scriptUrl(DataFlow::Node node, InputState state) {
  scriptUrlSink(node) and state.controlsStart()
}

predicate scriptUrlBarrier(DataFlow::Node node) {
  urlBarrier(node) or afterFixedHost(node) or notJavascriptUrl(node)
}

module HtmlFlow = InputFlow<html/2, htmlBarrier/1>;

module ScriptUrlFlow = InputFlow<scriptUrl/2, scriptUrlBarrier/1>;

from DataFlow::Node source, DataFlow::Node sink, string what
where
  HtmlFlow::flow(source, sink) and what = "is written into the page as HTML"
  or
  ScriptUrlFlow::flow(source, sink) and
  // a path starts with "/", so it's never a javascript: URL
  not pathInput(source) and
  what = "becomes a URL that can run a javascript: URL"
select sink, "Text from $@ " + what + ".", source, inputName(source)
