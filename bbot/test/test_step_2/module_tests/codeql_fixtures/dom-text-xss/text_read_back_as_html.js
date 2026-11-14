// text the page reads back from the document, written out as HTML
(function () {
  var input = document.getElementById("comment");
  document.getElementById("preview").innerHTML = input.value; // $ dom-text-xss
  $("#title").html($("#title-input").val()); // $ dom-text-xss
  var heading = document.querySelector("h1").textContent;
  document.getElementById("crumb").innerHTML = "<b>" + heading + "</b>"; // $ dom-text-xss
})();
