// VULNERABLE: document.URL flows to outerHTML
var url = document.URL;
var idx = url.indexOf("msg=");
if (idx !== -1) {
    var msg = decodeURIComponent(url.substring(idx + 4));
    document.getElementById("banner").outerHTML = "<div>" + msg + "</div>";
}
