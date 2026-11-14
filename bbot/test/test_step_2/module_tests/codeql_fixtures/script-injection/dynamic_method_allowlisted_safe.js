// the requested name is only used if it's one of the page's own handlers
(function () {
  var handlers = {
    open: function () {},
    close: function () {},
  };
  var name = new URLSearchParams(location.search).get("do");
  if (Object.prototype.hasOwnProperty.call(handlers, name)) {
    handlers[name]();
  }
})();
