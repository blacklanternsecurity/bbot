// objects without a prototype have nothing to pollute: __proto__ is just a key on them
(function () {
  var result = Object.create(null);
  location.search.slice(1).split("&").forEach(function (pair) {
    var parts = pair.split("=");
    var path = decodeURIComponent(parts[0]).split(".");
    var current = result;
    for (var i = 0; i < path.length - 1; i++) {
      current = current[path[i]] = current[path[i]] || Object.create(null);
    }
    current[path[path.length - 1]] = decodeURIComponent(parts[1] || "");
  });
  window.query = result;
})();
