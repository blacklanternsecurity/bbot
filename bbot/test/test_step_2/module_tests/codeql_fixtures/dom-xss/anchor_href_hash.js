// a link on the page takes its target from the fragment, so javascript: URLs run when it's clicked
(function () {
  var back = document.getElementById("backLink");
  back.href = location.hash.slice(1); // $ dom-xss
})();
