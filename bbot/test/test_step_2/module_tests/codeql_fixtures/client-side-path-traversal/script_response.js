// a parameter picks a translation script, which is run
fetch("/locales/" + new URLSearchParams(location.search).get("lang") + ".js")
  .then((response) => response.text())
  .then((code) => {
    eval(code); // $ client-side-path-traversal
  });
