// the page parses its query string with jquery-deparam
(function () {
  var params = deparam(location.search.substring(1));
  if (params.debug) {
    console.log(params);
  }
})();
