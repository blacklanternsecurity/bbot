// VULNERABLE: Object.fromEntries() keeps the decoded values entries() yields
const query = Object.fromEntries(new URLSearchParams(location.search).entries());
document.getElementById("title").innerHTML = query.title;
