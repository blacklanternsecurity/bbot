// handlers that send the request's Origin back as the allowed origin
var express = require("express");
var app = express();
app.get("/api/data", function (req, res) {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin); // $ cors-misconfiguration
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.json({ secret: "sensitive data" });
});
app.get("/api/profile", function (req, res) {
  res.header("Access-Control-Allow-Origin", req.get("origin")); // $ cors-misconfiguration
  res.header("Access-Control-Allow-Credentials", "true");
  res.json({});
});
app.use(function (req, res, next) {
  var origin = req.headers["origin"];
  res.set({ "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true" }); // $ cors-misconfiguration
  next();
});
