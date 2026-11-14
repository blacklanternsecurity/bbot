// event handlers written as attributes run their text as code; a property set to a string doesn't
(function ($) {
  var q = new URLSearchParams(location.search).get("action");
  var button = document.getElementById("go");
  button.setAttribute("onclick", q); // $ script-injection
  $("#help").attr("onmouseover", location.hash.slice(1)); // $ script-injection
  button.onclick = q;
})(jQuery);
