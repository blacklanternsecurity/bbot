// the fragment only goes in the query, which can't change the path
fetch("/search?q=" + location.hash.slice(1))
  .then((response) => response.text())
  .then((html) => {
    document.getElementById("results").innerHTML = html;
  });
