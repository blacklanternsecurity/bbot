// VULNERABLE: the decoded query string is parsed and merged recursively
function deepAssign(target, source) {
    for (var key in source) {
        if (typeof source[key] === "object" && source[key] !== null) {
            if (!target[key]) target[key] = {};
            deepAssign(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

var settings = JSON.parse(decodeURIComponent(location.search.substring(1)));
deepAssign({}, settings);
