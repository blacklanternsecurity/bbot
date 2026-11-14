// VULNERABLE: AngularJS URL whitelist allows javascript: URIs
angular.module("myApp").config(function($sceDelegateProvider) {
    $sceDelegateProvider.resourceUrlWhitelist(["self", "javascript:**"]);
});
