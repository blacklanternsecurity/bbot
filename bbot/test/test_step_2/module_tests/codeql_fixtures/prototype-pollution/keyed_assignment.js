// two attacker-chosen keys pick an object and a property: section=__proto__&key=isAdmin
(function () {
  var params = new URLSearchParams(location.search);
  var prefs = { display: {}, privacy: {} };
  var section = params.get("section");
  var key = params.get("key");
  prefs[section][key] = params.get("value"); // $ prototype-pollution
  prefs[section][key + "_enabled"] = true; // $ prototype-pollution
})();
