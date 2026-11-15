// A router rebuilding the page's location from its pieces. Cut where it finds a "?" or "#", the query string and the
// fragment keep that "?" or "#", so the location it goes to starts with one, and the attacker doesn't choose where.
function parsePath(path) {
  var pathname = path || "/";
  var search = "";
  var hash = "";
  var hashIndex = pathname.indexOf("#");
  if (hashIndex !== -1) {
    hash = pathname.substr(hashIndex);
    pathname = pathname.substr(0, hashIndex);
  }
  var searchIndex = pathname.indexOf("?");
  if (searchIndex !== -1) {
    search = pathname.substr(searchIndex);
    pathname = pathname.substr(0, searchIndex);
  }
  return { pathname: pathname, search: search, hash: hash };
}

var here = parsePath(location.search + location.hash);
location.replace(here.search + here.hash);

// one past the "#" is the attacker's own text
var url = location.href;
location.href = url.substr(url.indexOf("#") + 1); // $ open-redirect
