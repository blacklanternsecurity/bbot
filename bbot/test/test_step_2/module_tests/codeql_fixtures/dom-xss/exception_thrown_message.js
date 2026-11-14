// an error built from the input, rendered by the handler that catches it
(function () {
  function validate(value) {
    if (!/^\w+$/.test(value)) {
      throw new Error("Invalid username: " + value);
    }
    return value;
  }
  try {
    validate(new URLSearchParams(location.search).get("user"));
  } catch (err) {
    document.getElementById("error").innerHTML = err.message; // $ dom-xss
  }
})();
