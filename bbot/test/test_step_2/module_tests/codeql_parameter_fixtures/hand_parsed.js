// a query string the page parses into a dictionary itself, and the parameters it reads from it by name
(function () {
  function parse() {
    var query = location.search.substr(1);
    var params = Object.create(null);
    // the URL to go back to comes last, and keeps everything after its "="
    var at = query.indexOf("returnTo");
    if (at > -1) {
      var rest = query.substr(at);
      var equals = rest.indexOf("=");
      params[rest.substring(0, equals)] = rest.substr(equals + 1);
      query = query.substring(0, at - 1);
    }
    query.split("&").forEach(function (pair) {
      var parts = decodeURIComponent(pair).split("=");
      params[parts[0]] = parts[1];
    });
    return { query: params };
  }
  const { query } = parse();
  // into the page's location: tested
  location.href = decodeURIComponent(query.returnTo);
  // written as HTML: tested
  document.getElementById("note").innerHTML = query.note;
  // only ever text: not tested
  document.getElementById("title").textContent = query.title;
})();

// a dictionary of the fragment's values: not the query's parameters
(function () {
  var values = {};
  location.hash.slice(1).split("&").forEach(function (pair) {
    var parts = pair.split("=");
    values[parts[0]] = decodeURIComponent(parts[1]);
  });
  document.getElementById("error").innerHTML = values.error_description;
})();

// the page's own dictionary of its own values: no parameters
(function () {
  var labels = {};
  labels[document.body.dataset.section] = "Home";
  document.getElementById("label").innerHTML = labels.home;
})();
