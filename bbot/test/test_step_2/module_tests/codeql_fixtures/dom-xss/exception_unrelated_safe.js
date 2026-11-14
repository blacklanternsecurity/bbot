// errors that carry nothing from the input
(function () {
  try {
    JSON.parse(decodeURIComponent(location.hash.substring(1)));
  } catch (e) {
    document.getElementById("a").textContent = "Error: " + e.message;
  }
  try {
    loadSettings();
  } catch (e) {
    document.getElementById("b").innerHTML = "Couldn't load settings: " + e.message;
  }
})();
