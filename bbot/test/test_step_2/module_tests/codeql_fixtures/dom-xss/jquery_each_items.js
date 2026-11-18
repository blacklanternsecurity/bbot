// each value in the fragment is written into the page, through $.each's callback
(function () {
  $.each(decodeURIComponent(location.hash.slice(1)).split(","), function (i, value) {
    document.getElementById("tags").innerHTML = value; // $ dom-xss
  });
})();
