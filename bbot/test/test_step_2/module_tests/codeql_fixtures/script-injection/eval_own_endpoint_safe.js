// the response to a fixed request comes from the site, not the attacker
(function () {
  var xhr = new XMLHttpRequest();
  xhr.open("GET", "/api/data", true);
  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4) {
      eval(xhr.responseText);
    }
  };
  xhr.send();
})();
