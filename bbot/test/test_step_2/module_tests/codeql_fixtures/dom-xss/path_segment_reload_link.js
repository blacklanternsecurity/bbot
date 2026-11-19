// A reload link made of the last segment of the page's path, with the whole URL after it to skip caches: a path
// ending in javascript:alert(1);' makes the link a javascript: URL, run when the link is clicked
(function () {
  function reloadUrl() {
    var url = location.href;
    var query = "?nocache=" + encodeURIComponent(url);
    var hash = url.indexOf("#");
    var search = url.indexOf("?");
    var end = hash > -1 && search > -1 ? Math.min(hash, search) : Math.max(hash, search);
    if (end > -1) {
      url = url.substring(0, end);
    }
    return url.substring(url.lastIndexOf("/") + 1) + query;
  }
  var reload = document.getElementById("errorReload");
  if (reload) {
    reload.href = reloadUrl(); // $ dom-xss
  }
})();
