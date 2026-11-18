// jQuery loads the view named in a parameter into the page
$("#main").load("/views/" + new URLSearchParams(location.search).get("view")); // $ client-side-path-traversal
