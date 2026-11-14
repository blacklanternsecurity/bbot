// VULNERABLE: URLSearchParams.get() (auto-decodes) flows to Function() constructor
var fn = new Function(new URLSearchParams(location.search).get("code"));
fn();
