// a message's options merged into the widget's
(function () {
  var options = { color: "blue" };
  function extend(target, source) {
    for (var key in source) {
      if (source[key] instanceof Object) {
        target[key] = extend(target[key] || {}, source[key]); // $ prototype-pollution
      } else {
        target[key] = source[key]; // $ prototype-pollution
      }
    }
    return target;
  }
  window.addEventListener("message", function (e) {
    extend(options, e.data);
  });
})();
