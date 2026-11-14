// a message that navigates the page
window.addEventListener("message", function (e) {
  if (e.data && e.data.redirect) {
    window.location.href = e.data.redirect; // $ open-redirect
  }
});
