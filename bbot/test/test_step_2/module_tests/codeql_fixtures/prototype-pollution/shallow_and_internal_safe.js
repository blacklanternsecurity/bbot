// copies that are one level deep, and a deep merge only ever given the page's own objects
(function () {
  var parsed = JSON.parse(new URLSearchParams(location.search).get("opts"));
  var shallow = Object.assign({}, parsed);
  var spread = Object.assign({}, { a: 1 }, parsed);
  var params = new URLSearchParams(location.search);
  var flat = {};
  flat[params.get("key")] = params.get("value");

  function deepClone(obj) {
    var result = {};
    for (var key in obj) {
      result[key] = typeof obj[key] === "object" && obj[key] !== null ? deepClone(obj[key]) : obj[key];
    }
    return result;
  }
  var defaults = deepClone({ theme: { color: "blue", size: 12 } });
  console.log(shallow, spread, flat, defaults);
})();
