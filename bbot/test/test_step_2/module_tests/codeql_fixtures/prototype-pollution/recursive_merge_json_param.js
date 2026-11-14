// JSON from a parameter merged recursively into the settings
(function () {
  function merge(target, source) {
    for (var key in source) {
      if (typeof source[key] === "object" && source[key] !== null) {
        if (!target[key]) target[key] = {};
        merge(target[key], source[key]);
      } else {
        target[key] = source[key]; // $ prototype-pollution
      }
    }
    return target;
  }
  var settings = { theme: "light" };
  merge(settings, JSON.parse(new URLSearchParams(location.search).get("config")));
})();
