// AngularJS's $location hands out decoded parameters
angular.module("app").controller("LoginCtrl", ["$location", "$window", function (loc, win) {
  var next = loc.search().next;
  if (next) {
    win.location.href = next; // $ dom-xss
  }
}]);
