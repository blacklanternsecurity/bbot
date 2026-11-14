// VULNERABLE: URL parameter flows to jQuery .append()
var searchParam = new URLSearchParams(location.search).get("q");
$("body").append("<div>" + searchParam + "</div>");
