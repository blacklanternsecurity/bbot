// jQuery never parses a string starting with "#" as HTML
(function () {
  var hash = decodeURIComponent(location.hash.substring(1));
  $("#" + hash).addClass("highlight");
})();
