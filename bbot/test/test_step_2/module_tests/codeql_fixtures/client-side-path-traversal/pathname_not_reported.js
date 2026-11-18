// pjax-style navigation fetches the page's own path, which the server would have sent anyway
fetch(location.pathname + "?partial=1")
  .then((response) => response.text())
  .then((html) => {
    document.getElementById("main").innerHTML = html;
  });
