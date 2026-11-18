// the response is only ever text
fetch("/notes/" + location.hash.slice(1))
  .then((response) => response.text())
  .then((text) => {
    document.getElementById("note").textContent = text;
  });
