// A selector with the decoded fragment in it. jQuery before 1.9 read markup anywhere in it as HTML (CVE-2012-6708),
// which retirejs reports; since 1.9, only a string starting with "<" is.
$(window).on("hashchange", function () {
  var post = $("section.blog-list h2:contains(" + decodeURIComponent(window.location.hash.slice(1)) + ")");
  if (post) post.get(0).scrollIntoView();
});
