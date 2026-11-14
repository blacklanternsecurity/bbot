// text read from the document, written back as text
(function () {
  var input = document.getElementById("comment");
  document.getElementById("preview").textContent = input.value;
  $("#title").text($("#title-input").val());
  // only an element, never the field's text, is passed to $()
  function wrap(x) {
    if (typeof x === "object") {
      return $(x);
    }
  }
  wrap($("textarea").val());
  // an object's own value, not a field's
  function Option(value) {
    this.value = value;
  }
  Option.prototype.toString = function () {
    return String(this.value);
  };
  document.getElementById("option").innerHTML = new Option("<b>bold</b>").toString();
})();
