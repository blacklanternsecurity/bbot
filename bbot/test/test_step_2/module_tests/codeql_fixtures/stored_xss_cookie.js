// VULNERABLE: cookie value flows to innerHTML
var cookies = document.cookie;
var name = cookies.split("username=")[1];
document.getElementById("profile").innerHTML = name;
