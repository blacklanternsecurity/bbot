// SCE left on, and allowlists naming the hosts they trust, injected by parameter name
angular.module("myApp").config(function ($sceProvider, $sceDelegateProvider) {
  $sceProvider.enabled(true);
  $sceDelegateProvider.resourceUrlWhitelist(["self", "https://trusted.example.com/**"]);
});
var feature = { enabled: function (on) {} };
feature.enabled(false);
