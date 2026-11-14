// decoded input written as text, never parsed as HTML
(function () {
  var name = new URLSearchParams(location.search).get("name");
  document.getElementById("a").textContent = name;
  document.getElementById("b").innerText = name;
  document.getElementById("c").setAttribute("title", name);
  document.getElementById("d").appendChild(document.createTextNode(name));
  document.getElementById("e").append(name);
  document.getElementById("f").after(name);
  $("#g").text(name);
  $("#h").val(name);
})();
