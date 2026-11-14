// a parameter cut out of document.URL, decoded, replacing an element
(function () {
  var url = document.URL;
  var idx = url.indexOf("msg=");
  if (idx !== -1) {
    var msg = decodeURIComponent(url.substring(idx + 4));
    document.getElementById("banner").outerHTML = "<div>" + msg + "</div>"; // $ dom-xss
  }
})();
