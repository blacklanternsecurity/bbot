// SAFE: URLSearchParams percent-encodes everything again when it becomes a string
const params = new URLSearchParams(location.search);
params.delete("page");
document.getElementById("next").innerHTML = '<a href="?' + params.toString() + '">next</a>';
document.getElementById("prev").innerHTML = `<a href="?${params}">previous</a>`;
