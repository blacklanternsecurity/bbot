// decoded input sanitized or escaped before it's parsed as HTML
(function () {
  var input = decodeURIComponent(location.hash.substring(1));
  document.getElementById("a").innerHTML = DOMPurify.sanitize(input);
  document.getElementById("b").innerHTML = encodeURIComponent(input);

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
  document.getElementById("c").innerHTML = "<p>" + escapeHtml(input) + "</p>";
  document.getElementById("d").innerHTML = parseInt(input, 10) + " items";
  // only word characters and dashes are left
  document.getElementById("e").innerHTML = input.replace(/[^\w-]+/g, "");
  // only a value that isn't a string gets this far
  if (typeof input !== "string") {
    document.getElementById("f").innerHTML = input;
  }
})();
