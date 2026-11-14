// VULNERABLE: jQuery plugin passes options directly to .html()
(function($) {
    $.fn.tooltip = function(options) {
        var settings = $.extend({content: ""}, options);
        this.each(function() {
            $(this).html(settings.content);
        });
        return this;
    };
})(jQuery);
