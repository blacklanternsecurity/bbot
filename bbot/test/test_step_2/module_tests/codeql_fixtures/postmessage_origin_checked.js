// SAFE: message event handler WITH origin check
window.addEventListener("message", function(event) {
    if (event.origin !== "https://trusted.example.com") return;
    document.getElementById("output").textContent = event.data;
});
