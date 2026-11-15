// A selector with the decoded fragment in it. jQuery before 1.9 parses markup anywhere in it as HTML, and with no jQuery
// among this page's code, the page may run one of those
$(window).on("hashchange", function () {
  var post = $("section.blog-list h2:contains(" + decodeURIComponent(window.location.hash.slice(1)) + ")"); // $ dom-xss
  if (post) post.get(0).scrollIntoView();
});
