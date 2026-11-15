// URLs checked for a javascript: scheme before they're used, the way React and embed scripts check them
(function () {
  var isJavaScriptProtocol =
    /^[\u0000-\u001F ]*j[\r\n\t]*a[\r\n\t]*v[\r\n\t]*a[\r\n\t]*s[\r\n\t]*c[\r\n\t]*r[\r\n\t]*i[\r\n\t]*p[\r\n\t]*t[\r\n\t]*:/i;
  function sanitizeURL(url) {
    return isJavaScriptProtocol.test("" + url) ? "javascript:void 0" : url;
  }
  var safeUrl = /^\s*(?!javascript:)(?:[\w+.-]+:|[^:/?#]*(?:[/?#]|$))/i;

  var target = decodeURIComponent(location.hash.slice(1));
  var frame = document.createElement("iframe");
  frame.src = safeUrl.test(target) ? target : undefined;
  document.body.appendChild(frame);
  var link = document.getElementById("profile");
  link.setAttribute("href", sanitizeURL(target));
  // a test for something else is no check at all
  link.href = /^\d+$/.test(target) ? "#" + target : target; // $ dom-xss
})();
