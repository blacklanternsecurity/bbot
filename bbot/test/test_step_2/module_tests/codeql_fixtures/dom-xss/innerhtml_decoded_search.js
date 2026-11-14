// the decoded query string rendered with innerHTML
(function () {
  var query = location.search.substring(1);
  document.getElementById("greeting").innerHTML = decodeURIComponent(query); // $ dom-xss
})();
