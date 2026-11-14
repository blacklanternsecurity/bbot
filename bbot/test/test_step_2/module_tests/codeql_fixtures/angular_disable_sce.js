// VULNERABLE: AngularJS SCE disabled
angular.module("myApp").config(function($sceProvider) {
    $sceProvider.enabled(false);
});
