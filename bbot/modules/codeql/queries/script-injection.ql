/**
 * @name Client-side code injection
 * @description Input an attacker controls is run as code, or names the script the page loads or the function it
 *              calls.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id bbot/script-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 */

import javascript
import Inputs
import Sinks
import Barriers

/**
 * Code needs no characters the browser encodes (alert(1)), so any input can be code, except a whole URL left
 * encoded: it starts "http:", a label, and the rest is a comment with no newline to end it.
 */
predicate code(DataFlow::Node node, InputState state) {
  codeSink(node) and (state.isDecoded() or state.controlsStart())
}

/** Loading a script from the attacker's host needs the attacker to choose the start of the URL. */
predicate scriptUrl(DataFlow::Node node, InputState state) { scriptLoadSink(node) and state.controlsStart() }

predicate scriptUrlBarrier(DataFlow::Node node) { urlBarrier(node) or afterFixedHost(node) }

module CodeFlow = InputFlow<code/2, codeBarrier/1>;

module ScriptUrlFlow = InputFlow<scriptUrl/2, scriptUrlBarrier/1>;

from DataFlow::Node source, DataFlow::Node sink, string what
where
  CodeFlow::flow(source, sink) and what = "is run as code"
  or
  ScriptUrlFlow::flow(source, sink) and what = "is the URL of a script the page loads"
select sink, "Text from $@ " + what + ".", source, inputName(source)
