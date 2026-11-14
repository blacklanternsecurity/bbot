// an OAuth callback hands its URL, with the code or token in it, to any opener
(function () {
  var target = window.opener || window.parent;
  var message = { type: "oauth-callback", url: window.location.href };
  target.postMessage(message, "*"); // $ postmessage-leak
  window.close();
})();
