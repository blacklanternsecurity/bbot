/**
 * @name DOM-based cross-site scripting
 * @description Input an attacker controls is written into the page as HTML, or becomes the URL of a link, form or
 *              frame, or of the page itself, where a javascript: URL runs as code.
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
import ScriptUrl

/** Markup needs <, so only decoded input can write it. */
predicate html(DataFlow::Node node, InputState state) { htmlSink(node) and state.isDecoded() }

module HtmlFlow = InputFlow<html/2, htmlBarrier/1>;

from DataFlow::Node source, DataFlow::Node sink, string what
where
  HtmlFlow::flow(source, sink) and what = "is written into the page as HTML"
  or
  ScriptUrlFlow::flow(source, sink) and
  // a path starts with "/", so it's never a javascript: URL
  not pathInput(source) and
  what = "becomes a URL that can run a javascript: URL"
select sink, "Text from $@ " + what + ".", source, inputName(source)
