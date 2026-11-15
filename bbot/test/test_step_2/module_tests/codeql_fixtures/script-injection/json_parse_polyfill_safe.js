// json2.js: a JSON.parse for browsers that have none, which evals text only after its regex has checked it is JSON
if (typeof JSON !== "object") {
  JSON = {};
}
if (typeof JSON.parse !== "function") {
  JSON.parse = function (text, reviver) {
    var j;
    text = String(text);
    if (
      /^[\],:{}\s]*$/.test(
        text
          .replace(/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g, "@")
          .replace(/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g, "]")
          .replace(/(?:^|:|,)(?:\s*\[)+/g, "")
      )
    ) {
      j = eval("(" + text + ")");
      return typeof reviver === "function" ? reviver(j) : j;
    }
    throw new SyntaxError("JSON.parse");
  };
}

window.addEventListener("message", function (event) {
  var settings = JSON.parse(event.data);
  document.title = settings.title;
});
