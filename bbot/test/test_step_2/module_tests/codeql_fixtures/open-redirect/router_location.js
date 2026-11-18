// a router's location, and a window passed in, behave like the page's own
function Login(props) {
  var next = props.location.search.split("next=")[1];
  if (next) {
    window.location.href = decodeURIComponent(next); // $ dom-xss
  }
}
function go(win) {
  win.location.assign(/redirect=([^&]*)/.exec(win.location.href)[1]); // $ dom-xss
}
// a router's copy of the path isn't taken as the attacker's: routing code passes it between its own functions
function reload(history) {
  window.location.assign(history.location.pathname);
}
