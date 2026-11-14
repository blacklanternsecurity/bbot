// VULNERABLE: URL parameter flows to window.open
var url = new URLSearchParams(location.search).get("url");
window.open(url);
