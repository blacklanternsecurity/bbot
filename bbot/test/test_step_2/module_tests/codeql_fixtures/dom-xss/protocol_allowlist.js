// A URL whose protocol is checked against fixed ones can't be a javascript: URL
(function () {
  function isValidProtocol(url) {
    switch (url && url.protocol) {
      case "http:":
      case "https:":
      case "mailto:":
        return true;
      default:
        return false;
    }
  }
  function validUrl(url) {
    try {
      var absolute = new URL(url, "https://example.com");
      if (isValidProtocol(absolute)) {
        return absolute;
      }
    } catch (e) {}
    return null;
  }

  var target = decodeURIComponent(location.hash.slice(1));
  var link = document.getElementById("download");
  if (validUrl(target)) {
    link.href = target;
  }
  function download(url) {
    if (!validUrl(url)) {
      return;
    }
    link.href = url + "#download";
  }
  download(target);
  if (new URL(target, location.href).protocol === "https:") {
    link.href = target;
  }
  if (["http:", "https:"].includes(new URL(target, location.href).protocol)) {
    link.href = target;
  }
  // but a check the other way round, or one whose answer is ignored, isn't one
  if (new URL(target, location.href).protocol !== "https:") {
    link.href = target; // $ dom-xss
  }
  validUrl(target);
  link.href = target; // $ dom-xss
})();
