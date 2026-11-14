// VULNERABLE: URLSearchParams.get() (auto-decodes) flows to document.write
var name = new URLSearchParams(window.location.search).get("name");
document.write("<h1>Hello " + name + "</h1>");
