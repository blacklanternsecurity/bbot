// a path can start with //evil.example, which the browser reads as another host
(function () {
  if (!sessionStorage.getItem("token")) {
    location.href = "/login?return=" + encodeURIComponent(location.pathname);
  } else {
    location.href = location.pathname; // $ open-redirect
  }
  if (location.search === "?next") {
    window.location = location.pathname + "?page=2"; // $ open-redirect
  }
})();
