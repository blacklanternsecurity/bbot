// VULNERABLE: URL parameter flows to setTimeout with string arg
var action = new URLSearchParams(location.search).get("action");
setTimeout("doAction('" + action + "')", 1000);
