// SAFE: ACAO set to a specific trusted origin
var express = require("express");
var app = express();
app.get("/api/data", function(req, res) {
    res.setHeader("Access-Control-Allow-Origin", "https://trusted.example.com");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.json({secret: "sensitive data"});
});
