// browsers percent-encode <, > and " in every part of the URL, so undecoded, none can open a tag
(function () {
  document.getElementById("a").innerHTML = location.search;
  document.getElementById("b").innerHTML = "<p>" + location.hash.substring(1) + "</p>";
  document.getElementById("c").innerHTML = location.pathname;
  document.getElementById("d").innerHTML = "<b>" + location.href + "</b>";
  document.getElementById("e").innerHTML = document.URL;
  document.getElementById("f").innerHTML = document.referrer;
  $("#g").html(location.hash);
})();
