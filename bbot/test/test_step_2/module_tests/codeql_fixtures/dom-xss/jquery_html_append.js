// parameters inserted with jQuery's html() and append()
(function ($) {
  var params = new URLSearchParams(location.search);
  $("#title").html(params.get("title")); // $ dom-xss
  $("body").append("<div>" + params.get("q") + "</div>"); // $ dom-xss
})(jQuery);
