// VULNERABLE: message event handler with no origin check
window.addEventListener("message", function(event) {
    document.getElementById("output").innerHTML = event.data;
});
