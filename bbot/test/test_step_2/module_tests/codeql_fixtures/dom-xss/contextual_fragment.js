// a parameter parsed into a document fragment and inserted
(function () {
  var template = new URLSearchParams(location.search).get("tpl");
  var fragment = document.createRange().createContextualFragment(template); // $ dom-xss
  document.body.appendChild(fragment);
})();
