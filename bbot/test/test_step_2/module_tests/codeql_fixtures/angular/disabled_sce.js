// AngularJS with Strict Contextual Escaping turned off, injected by parameter name
angular.module("myApp").config(function ($sceProvider) {
  $sceProvider.enabled(false); // $ angular-misconfiguration
});
