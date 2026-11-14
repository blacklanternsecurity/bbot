// VULNERABLE: a URL's searchParams decode like URLSearchParams
const url = new URL(window.location.href);
document.getElementById("name").innerHTML = url.searchParams.get("name");
