// the Navigation API
(function () {
  navigation.navigate(new URLSearchParams(location.search).get("to")); // $ open-redirect
})();
