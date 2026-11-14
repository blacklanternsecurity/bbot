// VULNERABLE: iterating a URLSearchParams yields decoded names and values
for (const [key, value] of new URLSearchParams(location.search)) {
  document.getElementById(key).innerHTML = value;
}
