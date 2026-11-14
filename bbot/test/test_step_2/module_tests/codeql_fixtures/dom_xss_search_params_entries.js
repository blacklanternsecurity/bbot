// VULNERABLE: Object.fromEntries() keeps the decoded values
const query = Object.fromEntries(new URLSearchParams(location.search));
document.getElementById("title").innerHTML = query.title;
