// the fragment picks which partial is fetched, and the partial is written into the page
fetch("/partials/" + location.hash.slice(1))
  .then((response) => response.text())
  .then((html) => {
    document.getElementById("content").innerHTML = html; // $ client-side-path-traversal
  });
