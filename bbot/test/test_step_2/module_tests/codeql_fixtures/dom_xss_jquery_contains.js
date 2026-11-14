// VULNERABLE: location.hash used in jQuery :contains selector
var hash = location.hash;
var items = $(":contains(" + hash + ")");
items.addClass("highlight");
