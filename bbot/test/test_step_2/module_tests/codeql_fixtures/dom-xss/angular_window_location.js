// AngularJS's $window is the window: setting its location sends the page there, a javascript: URL included
angular.module("app").run(["$location", "$window", function (loc, win) {
  var next = loc.search().next;
  if (next) {
    win.location = next; // $ dom-xss
  }
}]);
