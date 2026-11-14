// SAFE: location.hash used as jQuery ID selector (prefixed with #)
var hash = location.hash.substring(1);
var element = $("#" + hash);
element.addClass("highlight");
