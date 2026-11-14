// objects that aren't elements, whatever they call their properties
(function () {
  function ErrorResponse(status, data) {
    this.status = status;
    this.data = data;
  }
  var input = decodeURIComponent(location.hash.slice(1));
  var response = new ErrorResponse(404, input);
  var image = { src: input, href: input };
  console.log(response, image);
})();
