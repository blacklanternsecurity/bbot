// whole URLs as keys: each starts with its scheme, so it's never __proto__ or constructor
(function () {
  var visits = {};
  var page = visits[location.href] || (visits[location.href] = {});
  page[document.URL] = Date.now();
})();
