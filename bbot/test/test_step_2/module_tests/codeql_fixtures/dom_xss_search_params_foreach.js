// VULNERABLE: URLSearchParams decodes the names and values forEach hands out
function showParams() {
  const params = new URLSearchParams(window.location.search);
  let output = "";
  params.forEach((value, key) => {
    output += `${key}: ${value}<br>`;
  });
  document.getElementById("output").innerHTML = output;
}
showParams();
