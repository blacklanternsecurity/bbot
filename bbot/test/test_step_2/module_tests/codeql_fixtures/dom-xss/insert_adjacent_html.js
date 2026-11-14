// a parameter appended to a list with insertAdjacentHTML
(function () {
  var params = new URLSearchParams(location.search);
  var list = document.getElementById("recent");
  list.insertAdjacentHTML("beforeend", "<li>" + params.get("item") + "</li>"); // $ dom-xss
})();
