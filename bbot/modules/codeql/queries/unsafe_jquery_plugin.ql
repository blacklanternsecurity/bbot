/**
 * @name Unsafe jQuery Plugin Option Handling
 * @description jQuery plugins that pass user-supplied options directly to dangerous
 *              jQuery methods (.html(), .append(), $()) without sanitization can
 *              enable DOM XSS when the plugin is called with attacker-controlled config.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id bbot/unsafe-jquery-plugin
 * @tags security
 *       external/cwe/cwe-079
 *       frameworks/jquery
 */

import javascript

module UnsafeJQueryPluginConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // jQuery plugin definition: $.fn.pluginName = function(options) { ... }
    exists(DataFlow::PropWrite pluginDef, DataFlow::FunctionNode fn |
      exists(DataFlow::PropRead fnProp |
        fnProp.getPropertyName() = "fn" and
        pluginDef.getBase() = fnProp
      ) and
      fn.flowsTo(pluginDef.getRhs()) and
      source = fn.getParameter(0)
    )
    or
    // $.extend(defaults, options) — the last options parameter
    exists(DataFlow::MethodCallNode extend |
      extend.getMethodName() = "extend" and
      source = extend.getArgument(extend.getNumArgument() - 1)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() in ["html", "append", "prepend", "after", "before", "replaceWith"] and
      sink = call.getArgument(0)
    )
    or
    exists(DataFlow::PropWrite prop |
      prop.getPropertyName() = "innerHTML" and
      sink = prop.getRhs()
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["sanitize", "encodeURIComponent"] and
      node = call
    )
  }
}

module UnsafeJQueryPluginFlow = TaintTracking::Global<UnsafeJQueryPluginConfig>;
import UnsafeJQueryPluginFlow::PathGraph

from UnsafeJQueryPluginFlow::PathNode source, UnsafeJQueryPluginFlow::PathNode sink
where UnsafeJQueryPluginFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "jQuery plugin option from $@ flows to a DOM manipulation sink without sanitization.",
  source.getNode(), "plugin options"
