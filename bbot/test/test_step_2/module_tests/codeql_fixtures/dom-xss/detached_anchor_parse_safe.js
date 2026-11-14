// a link that's never added to the page, used to read a URL's parts
(function () {
  function hostnameOf(url) {
    var a = document.createElement("a");
    a.href = url;
    return a.hostname;
  }
  var from = hostnameOf(document.referrer);
  var next = hostnameOf(new URLSearchParams(location.search).get("next"));
  console.log(from, next);
})();
