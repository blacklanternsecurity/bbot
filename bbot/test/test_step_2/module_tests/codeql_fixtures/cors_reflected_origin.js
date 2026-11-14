// VULNERABLE: Express handler reflects request origin in ACAO header
var express = require("express");
var app = express();
app.get("/api/data", function(req, res) {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.json({secret: "sensitive data"});
});
