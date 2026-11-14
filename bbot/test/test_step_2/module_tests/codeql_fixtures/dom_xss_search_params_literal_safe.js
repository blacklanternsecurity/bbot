// SAFE: these parameters come from the page's own code, not its URL
function showView() {
  const defaults = new URLSearchParams("view=grid&sort=name");
  document.getElementById("view").innerHTML = defaults.get("view");
}
showView();
