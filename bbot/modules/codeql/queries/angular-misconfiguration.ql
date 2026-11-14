/**
 * @name AngularJS escaping turned off
 * @description AngularJS's Strict Contextual Escaping is disabled, or its resource URL allowlist lets javascript:,
 *              data: or any URL through, removing the defense against injected bindings.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 5.0
 * @precision high
 * @id bbot/angular-misconfiguration
 * @tags security
 *       external/cwe/cwe-116
 */

import javascript
import Angular

from DataFlow::MethodCallNode call, string problem
where
  call = injected("$sceProvider").getAMethodCall("enabled") and
  forex(boolean on | on = call.getArgument(0).analyze().getABooleanValue() | on = false) and
  problem = "Strict Contextual Escaping is turned off"
  or
  call = injected("$sceDelegateProvider").getAMethodCall(["resourceUrlWhitelist", "trustedResourceUrlList"]) and
  exists(string url |
    url = call.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getAnElement().getStringValue()
  |
    url.regexpMatch("(?i).*(javascript|data):.*") or url = ["*", "**"]
  ) and
  problem = "the resource URL allowlist lets javascript:, data: or any URL through"
select call, "AngularJS: " + problem + "."
