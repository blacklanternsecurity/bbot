// a back link whose href comes from the query string
$(function () {
  $("#backLink").attr("href", new URLSearchParams(window.location.search).get("returnPath")); // $ dom-xss
});
