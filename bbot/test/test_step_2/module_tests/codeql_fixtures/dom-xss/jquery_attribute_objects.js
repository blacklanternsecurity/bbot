// jQuery attributes given as an object, on links (which run javascript: URLs) and an image (which doesn't)
(function ($) {
  var url = location.search.substr(1);
  $("<a>", { href: url, text: "Continue" }).appendTo("body"); // $ dom-xss
  $("#back").attr({ href: url }); // $ dom-xss
  $("<img>", { src: url }).appendTo("body");
})(jQuery);
