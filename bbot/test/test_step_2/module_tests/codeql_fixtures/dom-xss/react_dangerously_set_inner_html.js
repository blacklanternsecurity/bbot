// compiled React: a parameter passed as raw HTML
(function () {
  var bio = new URLSearchParams(location.search).get("bio");
  function Profile() {
    return React.createElement("div", { className: "bio", dangerouslySetInnerHTML: { __html: bio } }); // $ dom-xss
  }
  ReactDOM.render(React.createElement(Profile), document.getElementById("root"));
})();
