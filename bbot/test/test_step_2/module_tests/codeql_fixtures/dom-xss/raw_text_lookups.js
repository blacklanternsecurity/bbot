// Elements found by their tag name: a title's, style's or textarea's content is never markup either
(function () {
  var title = decodeURIComponent(location.hash.slice(1));
  document.getElementsByTagName("title")[0].innerHTML = title.replace("<", "&lt;");
  document.querySelector("style").innerHTML = title;
  document.querySelectorAll("textarea")[0].innerHTML = title;
  // but a div's is
  document.getElementsByTagName("div")[0].innerHTML = title; // $ dom-xss
})();
