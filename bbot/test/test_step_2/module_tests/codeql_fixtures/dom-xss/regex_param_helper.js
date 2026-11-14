// the common getParameterByName helper, used in another function
(function () {
  function getParameterByName(name) {
    var match = new RegExp("[?&]" + name + "=([^&#]*)").exec(window.location.search);
    return match && decodeURIComponent(match[1].replace(/\+/g, " "));
  }

  function showError(container, text) {
    container.innerHTML = '<p class="error">' + text + "</p>"; // $ dom-xss
  }

  var error = getParameterByName("error");
  if (error) {
    showError(document.getElementById("errors"), error);
  }
})();
