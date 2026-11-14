// the response to a request built from the query string is evaluated
(function () {
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function () {
    if (this.readyState === 4 && this.status === 200) {
      eval("var searchResultsObj = " + this.responseText); // $ script-injection
      displaySearchResults(searchResultsObj);
    }
  };
  xhr.open("GET", "/search-results" + window.location.search);
  xhr.send();
})();
