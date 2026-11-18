// one iteration helper, called twice: a field's text goes to one callback, and the table's rows to the other
(function () {
  function each(items, callback) {
    for (var i = 0; i < items.length; i++) {
      if (callback.call(items[i], i, items[i]) === false) break;
    }
    return items;
  }
  function forEachItem(items, callback) {
    items.forEach(callback);
  }
  each(document.getElementById("sort").value.split(","), function (i, column) {
    console.log(column);
  });
  each(document.querySelectorAll("tr"), function () {
    $(this).addClass("row");
  });
  forEachItem(document.getElementById("filter").value.split(","), function (term) {
    console.log(term);
  });
  forEachItem(Array.from(document.querySelectorAll("td")), function (cell) {
    $(cell).addClass("cell");
  });
})();
