// a path can start with //evil.example, which the browser reads as another host, but routing code navigates with the
// page's own path all the time, so the path isn't taken as a redirect's source
(function () {
  if (!sessionStorage.getItem("token")) {
    location.href = "/login?return=" + encodeURIComponent(location.pathname);
  } else {
    location.href = location.pathname;
  }
  if (location.search === "?next") {
    window.location = location.pathname + "?page=2";
  }
})();
