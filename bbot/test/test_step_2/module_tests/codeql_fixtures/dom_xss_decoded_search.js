// VULNERABLE: the query string is decoded before it reaches innerHTML
var query = location.search.substring(1);
document.getElementById("greeting").innerHTML = decodeURIComponent(query);
