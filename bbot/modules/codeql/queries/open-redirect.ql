/**
 * @name Client-side open redirect
 * @description Input an attacker controls becomes the location the page navigates to. One it can start, which a
 *              javascript: URL runs from, is dom-xss.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision high
 * @id bbot/open-redirect
 * @tags security
 *       external/cwe/cwe-601
 */

import javascript
import Inputs
import Sinks
import Barriers
import ScriptUrl

/** Sending the page elsewhere needs the attacker to choose the start of the URL. */
predicate navigation(DataFlow::Node node, InputState state) { navigationSink(node) and state.controlsStart() }

predicate barrier(DataFlow::Node node) { urlBarrier(node) or afterFixedHost(node) }

module NavigationFlow = InputFlow<navigation/2, barrier/1>;

from DataFlow::Node source, DataFlow::Node sink
where
  NavigationFlow::flow(source, sink) and
  // a path can start with //evil.example, but routers navigate with the page's own path all the time
  not pathInput(source) and
  // one the attacker can start runs a javascript: URL, which dom-xss reports
  not ScriptUrlFlow::flow(source, sink)
select sink, "Text from $@ becomes the location the page goes to.", source, inputName(source)
