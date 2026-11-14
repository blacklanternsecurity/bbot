// query string libraries: parse() decodes the parameters, extract() returns the query without its "?"
(function () {
  if (location.hash === "#a") location.href = queryString.parse(location.search).next; // $ open-redirect
  if (location.hash === "#b") location.href = queryString.extract(location.search); // $ open-redirect
})();
