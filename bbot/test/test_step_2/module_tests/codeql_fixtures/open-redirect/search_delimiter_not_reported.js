// A page sending its own URL on with ".md" put before the query and fragment. search(/[?#]/) finds where they start,
// so the part cut from there keeps its "?" or "#", and the attacker doesn't choose where the page goes.
function toMarkdownUrl(url) {
  var at = url.search(/[?#]/);
  return at < 0 ? url + ".md" : url.slice(0, at) + ".md" + url.slice(at);
}
window.open(toMarkdownUrl(window.location.href), "_blank");

// one past it is the attacker's own text
var href = location.href;
location.href = href.slice(href.search(/[?#]/) + 1); // $ dom-xss
