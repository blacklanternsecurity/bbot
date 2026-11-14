// VULNERABLE: the last path segment is decoded and evaluated
var segment = location.pathname.split("/").pop();
eval(decodeURI(segment));
