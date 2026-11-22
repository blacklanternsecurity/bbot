// Handlers that hand the event to a function to check where it came from: an exact comparison of its origin is a
// check, finding a substring in it isn't
var Messages = {
  allowed: ["https://partner.example.com"],
  CheckMessageOrigin: function (e) {
    return e.origin === location.origin || Messages.allowed.indexOf(e.origin) > -1;
  },
};
function onMessage(e) {
  if (!Messages.CheckMessageOrigin(e)) {
    console.warn("Refusing to handle cross-origin message: %s", e.data);
    return;
  }
  document.location.href = e.data.split("|")[1];
}
window.addEventListener("message", onMessage);

function looselyChecked(e) {
  return e.origin.indexOf("example.com") !== -1;
}
window.addEventListener("message", function (e) {
  if (!looselyChecked(e)) return;
  document.location.href = e.data; // $ dom-xss
});
