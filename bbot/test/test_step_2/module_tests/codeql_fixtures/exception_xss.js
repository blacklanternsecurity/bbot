// VULNERABLE: exception message rendered into DOM via innerHTML
try {
    JSON.parse(decodeURIComponent(location.hash.substring(1)));
} catch(e) {
    document.getElementById("error").innerHTML = "Error: " + e.message;
}
