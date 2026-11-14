// SAFE: merge with __proto__ guard
function safeMerge(target, source) {
    for (var key in source) {
        if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
        if (typeof source[key] === "object" && source[key] !== null) {
            if (!target[key]) target[key] = {};
            safeMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

var params = JSON.parse(new URLSearchParams(location.search).get("config"));
safeMerge({}, params);
