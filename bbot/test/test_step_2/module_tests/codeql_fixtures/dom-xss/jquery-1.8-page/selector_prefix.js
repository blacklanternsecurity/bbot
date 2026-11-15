// This page runs jQuery 1.8, which parses markup anywhere after the selector text as HTML (CVE-2012-6708)
$(window).on("hashchange", function () {
  var section = decodeURIComponent(window.location.hash.slice(1));
  $("section.blog-list h2:contains(" + section + ")").get(0).scrollIntoView(); // $ dom-xss
  $(".module-" + section).show(); // $ dom-xss
  // a "#" first stops it, as in every version
  $("#" + section).addClass("highlight");
});
