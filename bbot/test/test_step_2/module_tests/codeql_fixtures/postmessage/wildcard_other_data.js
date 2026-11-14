// other data the page computes, posted to any origin
(function () {
  var config = { appId: window.APP_ID, version: "5.2.7" };
  parent.postMessage({ type: "sdk:info", config: config }, "*"); // $ postmessage-wildcard
  parent.postMessage({ type: "resize", height: document.body.scrollHeight }, "*"); // $ postmessage-wildcard
})();
