// a message evaluated by a handler that never checks where it came from
window.addEventListener("message", function (event) {
  if (event.data.type === "exec") {
    eval(event.data.code); // $ script-injection
  }
});
