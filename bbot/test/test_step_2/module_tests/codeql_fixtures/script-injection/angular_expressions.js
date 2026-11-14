// AngularJS evaluates and compiles expressions from the query string
angular.module("app").controller("SearchCtrl", ["$scope", "$compile", function (scope, compile) {
  var expr = new URLSearchParams(location.search).get("expr");
  scope.$eval(expr); // $ script-injection
  compile("<div>" + expr + "</div>")(scope); // $ script-injection
  scope.$eval("total = 0");
}]);
