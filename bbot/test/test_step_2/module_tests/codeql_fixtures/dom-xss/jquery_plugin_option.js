// a page's own tooltip plugin, given a URL parameter as its content
(function ($) {
  $.fn.tooltip = function (options) {
    var settings = $.extend({ content: "" }, options);
    return this.each(function () {
      $(this).html(settings.content); // $ dom-xss
    });
  };

  $(".help").tooltip({ content: new URLSearchParams(location.search).get("tip") });
})(jQuery);
