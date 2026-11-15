// This page runs jQuery 3. Since 1.9, $() reads a string as HTML only when it starts with "<", so these are selectors
(function () {
  var section = decodeURIComponent(location.hash.slice(1));
  $(".module-" + section).show();
  $('a[data-id="' + section + '"] span.extension').hide();
  // but markup, or the input alone, is still HTML
  $("<div>" + section + "</div>").appendTo("body"); // $ dom-xss
  $("  <p>" + section).appendTo("body"); // $ dom-xss
  $(section).appendTo("body"); // $ dom-xss
})();
