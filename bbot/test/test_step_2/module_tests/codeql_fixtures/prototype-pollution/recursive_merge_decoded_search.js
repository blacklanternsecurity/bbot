// the decoded query string parsed as JSON and merged recursively
(function () {
  function deepAssign(target, source) {
    Object.keys(source).forEach(function (key) {
      if (source[key] && typeof source[key] === "object") {
        target[key] = target[key] || {};
        deepAssign(target[key], source[key]);
      } else {
        target[key] = source[key]; // $ prototype-pollution
      }
    });
    return target;
  }
  deepAssign({}, JSON.parse(decodeURIComponent(location.search.substring(1))));
})();
