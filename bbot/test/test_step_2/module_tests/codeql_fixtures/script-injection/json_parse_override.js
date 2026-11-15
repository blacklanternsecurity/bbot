// a JSON.parse replaced outright, even where the browser has its own, that runs whatever text it is given
if (typeof JSON !== "object") {
  JSON = {};
}
JSON.parse = function (text) {
  return eval("(" + text + ")"); // $ script-injection
};

window.addEventListener("message", function (event) {
  var settings = JSON.parse(event.data);
  document.title = settings.title;
});
