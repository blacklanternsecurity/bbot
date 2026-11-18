// the scheme comes first, so the parameter picks the host but can never make a javascript: URL
(function () {
  location.href = "https://" + new URLSearchParams(location.search).get("host") + "/welcome"; // $ open-redirect
})();
