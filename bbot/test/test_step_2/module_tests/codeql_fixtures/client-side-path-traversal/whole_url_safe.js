// the whole URL starts with the page's own origin, so it can't climb out of the path it's put in
var xhr = new XMLHttpRequest();
xhr.open("GET", "/render/" + location.href);
xhr.onload = function () {
  document.getElementById("preview").innerHTML = xhr.responseText;
};
xhr.send();
