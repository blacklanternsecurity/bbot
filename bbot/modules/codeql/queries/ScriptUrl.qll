/**
 * Input that can start a URL the page follows or loads: a link, form or frame, or the page's own location. A
 * javascript: URL there runs as code, so it's DOM XSS rather than only an open redirect.
 */

import javascript
import Inputs
import Sinks
import Barriers

/** A javascript: URL needs the attacker to choose the start of the URL. */
predicate scriptUrl(DataFlow::Node node, InputState state) {
  (scriptUrlSink(node) or scriptNavigationSink(node)) and state.controlsStart()
}

predicate scriptUrlBarrier(DataFlow::Node node) {
  urlBarrier(node) or afterFixedHost(node) or notJavascriptUrl(node)
}

module ScriptUrlFlow = InputFlow<scriptUrl/2, scriptUrlBarrier/1>;
