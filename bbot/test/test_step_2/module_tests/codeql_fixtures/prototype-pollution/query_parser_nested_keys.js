// a hand-written query string parser that builds nested objects from a[b][c]=d
(function () {
  function parseQuery(query) {
    var result = {};
    query.replace(/^\?/, "").split("&").forEach(function (pair) {
      var parts = pair.split("=");
      var path = decodeURIComponent(parts[0]).replace(/\]/g, "").split("[");
      var value = decodeURIComponent(parts[1] || "");
      var current = result;
      for (var i = 0; i < path.length - 1; i++) {
        current = current[path[i]] = current[path[i]] || {};
      }
      current[path[path.length - 1]] = value; // $ prototype-pollution
    });
    return result;
  }
  window.config = parseQuery(location.search);
})();
