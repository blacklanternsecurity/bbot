// VULNERABLE: XHR responseText flows to eval
var xhr = new XMLHttpRequest();
xhr.open("GET", "/api/data", true);
xhr.onreadystatechange = function() {
    if (xhr.readyState === 4) {
        eval(xhr.responseText);
    }
};
xhr.send();
