// a return URL matched out of the location
(function () {
  var returnUrl = /url=(https?:\/\/.+)/.exec(location);
  location.href = returnUrl ? returnUrl[1] : "/"; // $ open-redirect
})();
