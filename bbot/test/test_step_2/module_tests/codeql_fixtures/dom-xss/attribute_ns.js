// an SVG link whose xlink:href comes from the query string
(function () {
  var data = JSON.parse(decodeURIComponent(window.location.search.substr(1)));
  var link = document.getElementById("logo-link");
  link.setAttributeNS("http://www.w3.org/1999/xlink", "href", data.p); // $ dom-xss
})();
