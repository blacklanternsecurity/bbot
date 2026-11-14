// VULNERABLE: location.hash flows to eval()
var code = location.hash.substring(1);
eval(code);
