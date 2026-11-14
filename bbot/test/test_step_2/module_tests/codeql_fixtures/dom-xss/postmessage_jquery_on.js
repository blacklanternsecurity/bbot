// a message handler registered through jQuery
$(window).on("message", function (e) {
  $("#chat").html(e.originalEvent.data.text); // $ dom-xss
});
