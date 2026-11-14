// handlers that allow a fixed origin, or only origins on a list
var express = require("express");
var app = express();
var allowed = ["https://app.example.com", "https://admin.example.com"];
app.get("/api/data", function (req, res) {
  res.setHeader("Access-Control-Allow-Origin", "https://trusted.example.com");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.json({});
});
app.get("/api/list", function (req, res) {
  var origin = req.headers.origin;
  if (allowed.indexOf(origin) !== -1) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.json({});
});
app.get("/api/public", function (req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.json({});
});
