// a query string parsed by hand into an Object.create(null) dictionary, as OAuth callback pages read the URL to go
// back to, and that URL as the page's location
(function () {
  function parseQuery() {
    var query = location.search.substr(1);
    var params = Object.create(null);
    // the return URL comes last and keeps everything after its "="
    var at = query.indexOf("returnUrl");
    if (at > -1) {
      var rest = query.substr(at);
      var equals = rest.indexOf("=");
      params[rest.substring(0, equals)] = rest.substr(equals + 1);
      query = query.substring(0, at - 1);
    }
    var pairs = query.split("&");
    for (var i = 0; i < pairs.length; i++) {
      var pair = decodeURIComponent(pairs[i]).split("=");
      params[pair[0]] = pair[1];
    }
    return { query: params };
  }
  const { query } = parseQuery();
  window.location.href = decodeURIComponent(query.returnUrl); // $ dom-xss
})();
