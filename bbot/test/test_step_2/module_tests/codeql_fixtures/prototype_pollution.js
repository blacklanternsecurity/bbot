// VULNERABLE: recursive merge allows __proto__ pollution
function merge(target, source) {
    for (var key in source) {
        if (typeof source[key] === "object" && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

var params = JSON.parse(new URLSearchParams(location.search).get("config"));
merge({}, params);
