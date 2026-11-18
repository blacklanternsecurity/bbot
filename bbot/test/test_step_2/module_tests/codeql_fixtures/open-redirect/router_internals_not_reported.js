// A router hands its own location around, as an object and as its parts, strips its base path off with slice(), and
// builds links on the page's own protocol and host. None of that is the attacker's, so none of it is reported.
function stripBasename(pathname, basename) {
  if (basename === "/") return pathname;
  return pathname.slice(basename.length) || "/";
}
function followLink(router, to, basename) {
  var current = router.location;
  var url = new URL(to, current.protocol + "//" + current.host);
  var path = stripBasename(url.pathname, basename);
  if (url.host !== current.host) {
    window.location.href = to;
  } else {
    window.location.href = path + url.search;
  }
}
function reloadCurrent(router, basename) {
  window.location.assign(stripBasename(router.location.pathname, basename));
}
