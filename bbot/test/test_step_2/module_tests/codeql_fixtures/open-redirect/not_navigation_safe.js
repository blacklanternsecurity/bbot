// methods and properties that share a name with a navigation, but don't navigate
(function () {
  var params = new URLSearchParams(location.search);
  var next = params.get("next");
  var a = document.createElement("a");
  a.href = document.referrer;
  var host = a.hostname;
  var label = "Return to " + host;
  label = label.replace(next, "");
  var settings = Object.assign({}, { next: next });
  var xhr = new XMLHttpRequest();
  xhr.open("GET", "/track?to=" + encodeURIComponent(next));
  xhr.send();
  var link = { href: next };
  console.log(label, settings, link);
})();
