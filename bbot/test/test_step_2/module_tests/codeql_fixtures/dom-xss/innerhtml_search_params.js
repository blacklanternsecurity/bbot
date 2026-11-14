// a search term rendered with innerHTML
(function () {
  var query = new URLSearchParams(window.location.search).get("search");
  var message = document.getElementById("searchMessage");
  message.innerHTML = "0 results for '" + query + "'"; // $ dom-xss
})();
