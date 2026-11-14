// a search term written into the page with document.write
(function () {
  var query = new URLSearchParams(window.location.search).get("search");
  if (query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '">'); // $ dom-xss
  }
})();
