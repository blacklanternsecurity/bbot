// the length of text from the document is a number, which holds no markup
(function () {
  var approvers = $("#approvers");
  $("#count").html(approvers.val().length + " approvers");
  var comment = document.getElementById("comment").value;
  document.getElementById("chars").innerHTML = comment.length + " characters";
})();
