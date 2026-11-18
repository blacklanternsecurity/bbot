// window.name, set by the page that opened this one, as the next location
(function () {
  if (window.name) {
    location.assign(window.name); // $ dom-xss
  }
})();
