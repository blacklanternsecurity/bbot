// VULNERABLE: localStorage value flows to innerHTML (stored XSS)
var savedName = localStorage.getItem("username");
document.getElementById("greeting").innerHTML = "Welcome back, " + savedName;
