// Links built from the page's own base URLs, with its path, or with input after them. A javascript: URL has to come
// first, and a path always starts with "/".
(function () {
  var bases = { web: "https://shop.example", app: "shopapp://" };
  var hash = decodeURIComponent(location.hash.slice(1));
  Object.keys(bases).forEach(function (kind) {
    var link = document.createElement("a");
    link.setAttribute("href", bases[kind] + location.pathname + location.search);
    link.setAttribute("title", "open");
    link.setAttribute("href", `${bases[kind]}${hash}`);
    document.body.appendChild(link);
  });
  var home = document.getElementById("home");
  home.href = location.pathname;
  // but input after nothing, after a value that may be empty, or after "javascript:" is still the attacker's
  home.href = "" + hash; // $ dom-xss
  home.href = "javascript:" + hash; // $ dom-xss
  var prefix = location.search ? "" : "/start/";
  home.href = prefix + hash; // $ dom-xss
})();
