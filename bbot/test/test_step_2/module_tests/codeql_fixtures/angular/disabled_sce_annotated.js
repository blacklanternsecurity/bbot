// the same, written the way minifiers need it, with the injected name as a string
angular.module("myApp").config(["$sceProvider", function (sce) {
  sce.enabled(!1); // $ angular-misconfiguration
}]);
