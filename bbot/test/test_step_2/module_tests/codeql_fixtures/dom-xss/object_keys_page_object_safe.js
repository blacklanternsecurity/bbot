// the keys of the page's own object are the page's, whatever values it stores
(function ($) {
  var obj = {};
  obj[Math.random()] = window.name;
  for (var p in obj) {
    $(p);
  }
})(jQuery);
