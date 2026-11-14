// a plugin that renders its options as HTML, only ever given the page's own strings
(function ($) {
  $.fn.badge = function (options) {
    var settings = $.extend({ label: "" }, options);
    return this.each(function () {
      $(this).html("<span>" + settings.label + "</span>");
    });
  };
  $(".new").badge({ label: "New!" });
})(jQuery);
