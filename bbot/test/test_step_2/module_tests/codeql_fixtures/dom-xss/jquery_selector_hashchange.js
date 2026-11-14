// jQuery parses a selector string holding markup as HTML
$(window).on("hashchange", function () {
  var post = $("section.blog-list h2:contains(" + decodeURIComponent(window.location.hash.slice(1)) + ")"); // $ dom-xss
  if (post) post.get(0).scrollIntoView();
});
