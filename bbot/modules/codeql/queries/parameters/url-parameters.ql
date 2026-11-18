/**
 * @name URL parameter reaching a sink
 * @description A URL parameter the page reads by name and passes somewhere a payload could act. Not a finding: the
 *              codeql module hands each name to the modules that test parameters, so DOMino can confirm it in the
 *              browser.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id bbot/url-parameter
 */

import javascript
import Inputs
import Sinks
import Barriers

module ParameterConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { namedParameter(node, _) }

  predicate isSink(DataFlow::Node node) {
    htmlSink(node) or
    scriptUrlSink(node) or
    navigationSink(node) or
    codeSink(node) or
    scriptLoadSink(node)
  }

  predicate isBarrier(DataFlow::Node node) { numeric(node) or encoded(node) }
}

module ParameterFlow = TaintTracking::Global<ParameterConfig>;

from DataFlow::Node read, string name
where namedParameter(read, name) and ParameterFlow::flow(read, _)
select read, name
