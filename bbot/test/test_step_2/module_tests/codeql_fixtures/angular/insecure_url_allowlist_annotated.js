// a resource URL allowlist that lets any URL through, with the injected name as a string
angular.module("otherApp").config(["$sceDelegateProvider", function (p) {
  p.trustedResourceUrlList(["**"]); // $ angular-misconfiguration
}]);
