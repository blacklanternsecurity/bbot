/**
 * @name AngularJS Security Misconfiguration
 * @description Detects AngularJS anti-patterns: disabling Strict Contextual Escaping (SCE)
 *              and configuring insecure URL whitelists that allow javascript: or data: URIs.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id bbot/angular-security
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 *       frameworks/angularjs
 */

import javascript

predicate isAngularMisconfig(Expr node, string message) {
  // $sceProvider.enabled(false) — disabling SCE
  exists(MethodCallExpr call |
    call = node and
    call.getMethodName() = "enabled" and
    call.getArgument(0).(BooleanLiteral).getValue() = "false" and
    call.getReceiver().(VarRef).getName() = "$sceProvider" and
    message = "SCE (Strict Contextual Escaping) is disabled via $sceProvider.enabled(false)"
  )
  or
  // $sceDelegateProvider.resourceUrlWhitelist() with dangerous patterns
  exists(MethodCallExpr call, ArrayExpr arr, Expr element |
    call = node and
    call.getMethodName() in ["resourceUrlWhitelist", "trustedResourceUrlList"] and
    arr = call.getArgument(0) and
    element = arr.getAnElement() and
    exists(string val |
      val = element.(StringLiteral).getValue() and
      (
        val.regexpMatch(".*javascript:.*") or
        val.regexpMatch(".*data:.*") or
        val = "**" or
        val = "*"
      )
    ) and
    message = "URL whitelist allows dangerous URI schemes (javascript:/data:) or overly broad wildcards"
  )
}

from Expr node, string message
where isAngularMisconfig(node, message)
select node, "AngularJS security misconfiguration: " + message + "."
