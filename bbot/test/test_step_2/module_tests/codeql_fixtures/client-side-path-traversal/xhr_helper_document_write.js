// the fragment picks the path of a request made through a helper, and the response replaces the page
function makeRequest() {
  return new XMLHttpRequest();
}

function showPage() {
  var path = document.URL.split("#")[1];
  var xhr = makeRequest();
  xhr.open("GET", "https://content.example.com/pages/" + path, true);
  xhr.send();
  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4 && xhr.status === 200) {
      document.open();
      document.write(xhr.responseText); // $ client-side-path-traversal
      document.close();
    }
  };
}
