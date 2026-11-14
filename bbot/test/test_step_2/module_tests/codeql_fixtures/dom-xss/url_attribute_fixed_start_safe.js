// the attacker only controls what comes after a fixed start, so the URL can't become javascript:
(function () {
  var params = new URLSearchParams(location.search);
  document.getElementById("a").href = "/search?q=" + params.get("q");
  document.getElementById("b").src = "https://cdn.example.com/img/" + encodeURIComponent(params.get("img"));
  document.getElementById("c").href = location.href;
  document.getElementById("d").href = document.referrer;
})();
