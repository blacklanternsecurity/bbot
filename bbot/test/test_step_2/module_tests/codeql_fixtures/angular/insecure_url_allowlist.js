// a resource URL allowlist that lets javascript: URLs through, injected by parameter name
angular.module("myApp").config(function ($sceDelegateProvider) {
  $sceDelegateProvider.resourceUrlWhitelist(["self", "javascript:**"]); // $ angular-misconfiguration
});
