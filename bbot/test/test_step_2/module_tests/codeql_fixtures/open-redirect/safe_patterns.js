// locations the attacker can't choose
(function () {
  var params = new URLSearchParams(location.search);
  var q = params.get("q");
  location.href = "/search?q=" + encodeURIComponent(q);
  location.href = "/dashboard";
  location.hash = q;
  location.href = document.referrer;
  location.href = location.href.split("#")[0];
  location.replace(location.origin + "/home");
})();
