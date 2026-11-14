// SAFE: exception message rendered via textContent
try {
    JSON.parse(decodeURIComponent(location.hash.substring(1)));
} catch(e) {
    document.getElementById("error").textContent = "Error: " + e.message;
}
