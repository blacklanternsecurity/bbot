// VULNERABLE: getAll() returns every decoded value of a parameter
const params = new URLSearchParams(location.search);
document.getElementById("tags").innerHTML = params.getAll("tag").join(", ");
