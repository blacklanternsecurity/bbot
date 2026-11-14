// SAFE: the browser percent-encodes the query string, and nothing decodes it
document.getElementById("search").innerHTML = location.search;
