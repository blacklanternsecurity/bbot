// A styling library reading the CSS in its own style tags, and writing it into a new style element through React
(function () {
  function _extends() {
    return Object.assign.apply(Object, arguments);
  }

  function styleElement() {
    var css = "";
    document.querySelectorAll("style[data-styles]").forEach(function (el) {
      css += el.textContent;
    });
    var props = {};
    props["data-styles"] = "";
    props.dangerouslySetInnerHTML = { __html: css };
    return React.createElement("style", _extends({}, props, { key: "styles" }));
  }

  styleElement();
})();
