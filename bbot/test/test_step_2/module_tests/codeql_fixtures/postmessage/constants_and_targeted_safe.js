// messages carrying nothing but constants, and messages sent to a named origin
(function () {
  parent.postMessage("ready", "*");
  (window.opener || window.parent).postMessage("[sdk]ready", "*");
  parent.postMessage({ type: "loaded", ok: true }, "*");
  parent.postMessage(location.href, "https://partner.example.com");
  window.opener.postMessage({ token: localStorage.getItem("access_token") }, location.origin);
})();
