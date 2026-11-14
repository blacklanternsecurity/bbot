// SAFE: AngularJS with SCE enabled (default) and restricted whitelist
angular.module("myApp").config(function($sceDelegateProvider) {
    $sceDelegateProvider.resourceUrlWhitelist(["self", "https://trusted.example.com/**"]);
});
