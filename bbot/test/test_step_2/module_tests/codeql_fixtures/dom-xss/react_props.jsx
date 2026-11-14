// JSX: a link's href runs javascript: URLs, a component's props are only its own
function Continue() {
  var next = new URLSearchParams(location.search).get("next");
  return <a href={next}>Continue</a>; // $ dom-xss
}
function Embed() {
  return <Player data={document.location.hash.substr(1)} />;
}
