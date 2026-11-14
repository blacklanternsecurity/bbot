// SAFE: jQuery plugin uses .text() instead of .html()
(function($) {
    $.fn.tooltip = function(options) {
        var settings = $.extend({content: ""}, options);
        this.each(function() {
            $(this).text(settings.content);
        });
        return this;
    };
})(jQuery);
