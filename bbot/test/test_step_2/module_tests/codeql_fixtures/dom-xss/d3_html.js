// d3 selections written as HTML, directly or from a function
(function () {
  var title = new URLSearchParams(location.search).get("title");
  d3.select("#chart-title").html(title); // $ dom-xss
  d3.selectAll(".label")
    .attr("class", "label active")
    .html(function () {
      return "<b>" + title + "</b>"; // $ dom-xss
    });
  d3.select("#caption").text(title);
})();
