// jQuery helpers that load or run code
(function ($) {
  var params = new URLSearchParams(location.search);
  $.getScript(params.get("module")); // $ script-injection
  $.globalEval(params.get("snippet")); // $ script-injection
})(jQuery);
