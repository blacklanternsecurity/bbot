// data a page keeps from other origins, posted to whichever page framed or opened it
(function () {
  parent.postMessage(location.href, "*"); // $ postmessage-leak
  window.opener.postMessage({ token: localStorage.getItem("access_token") }, "*"); // $ postmessage-leak
  parent.postMessage(document.cookie, "*"); // $ postmessage-leak
  window.parent.postMessage(JSON.stringify({ type: "auth", hash: location.hash }), "*"); // $ postmessage-leak
  top.postMessage({ session: sessionStorage.getItem("session") }, "*"); // $ postmessage-leak
})();
