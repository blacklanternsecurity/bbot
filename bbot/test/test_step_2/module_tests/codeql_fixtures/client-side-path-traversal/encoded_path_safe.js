// the fragment is encoded, slashes and all, so it can't leave the directory
fetch("/items/" + encodeURIComponent(location.hash.slice(1)))
  .then((response) => response.text())
  .then((html) => {
    document.getElementById("item").innerHTML = html;
  });
