// a message picks the URL an embedded player loads
window.addEventListener("message", function (e) {
  var iframe = document.createElement("iframe");
  var player = { element: iframe };
  var d;
  document.body.appendChild(iframe);
  try {
    d = JSON.parse(e.data);
  } catch (err) {
    return;
  }
  switch (d.type) {
    case "page-load":
      player.element.scrollIntoView();
      break;
    case "load-channel":
      player.element.src = d.url; // $ dom-xss
      break;
  }
}, false);
