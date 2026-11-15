// What's written into an element whose content is never markup, like a style or a textarea, is only ever text. So is
// React's dangerouslySetInnerHTML on one, even when its props are copied first.
(function () {
  var css = decodeURIComponent(location.hash.slice(1));

  var style = document.createElement("style");
  style.innerHTML = css;
  var note = document.createElement("textarea");
  note.innerHTML = css;
  note.setHTMLUnsafe(css);

  React.createElement("style", { dangerouslySetInnerHTML: { __html: css } });
  var props = {};
  props.dangerouslySetInnerHTML = { __html: css };
  React.createElement("style", Object.assign({}, props, { key: "styles" }));

  // but outerHTML is parsed where the element stands, and a div's content is markup
  style.outerHTML = css; // $ dom-xss
  document.createElement("div").innerHTML = css; // $ dom-xss
})();
