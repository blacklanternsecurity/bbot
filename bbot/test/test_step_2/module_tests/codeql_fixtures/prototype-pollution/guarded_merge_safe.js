// merges that refuse the keys that reach a prototype
(function () {
  function safeMerge(target, source) {
    for (var key in source) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
      if (typeof source[key] === "object" && source[key] !== null) {
        if (!target[key]) target[key] = {};
        safeMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }
  safeMerge({}, JSON.parse(new URLSearchParams(location.search).get("config")));

  // skips __proto__, and only recurses into plain objects, so constructor.prototype is replaced, never written to
  function isPlainObject(value) {
    return typeof value === "object" && Object.prototype.toString.call(value) === "[object Object]";
  }
  function plainMerge() {
    var target = arguments[0];
    if (!isPlainObject(target)) target = {};
    for (var i = 1; i < arguments.length; i++) {
      var source = arguments[i];
      if (isPlainObject(source)) {
        for (var key in source) {
          if (key === "__proto__" || target === source[key]) continue;
          target[key] = isPlainObject(source[key]) ? plainMerge(target[key], source[key]) : source[key];
        }
      }
    }
    return target;
  }
  plainMerge({}, JSON.parse(decodeURIComponent(location.hash.slice(1))));
})();
