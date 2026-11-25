// the keys of the page's own Object.create(null) dictionary are the page's, whatever values it stores
(function ($) {
  var dictionary = Object.create(null);
  dictionary[Math.random()] = window.name;
  for (var key in dictionary) {
    $(key);
  }
  Object.keys(dictionary).forEach(function (name) {
    $(name);
  });
  // a value the page chose, under a key from the URL
  var pages = Object.create(null);
  pages[location.hash.slice(1)] = "/home";
  location.href = pages.home;
})(jQuery);
