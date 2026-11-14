// SAFE: recursive merge exists in bundled library code but is never
// called with user-controlled data. This mimics the real-world pattern
// of webpack-bundled libraries (Immer, TypeScript helpers, lodash, etc.)
// that contain merge-like functions used only internally.

// --- Simulated bundled library code ---
function deepClonePatchValue(obj) {
    var result = {};
    for (var key in obj) {
        if (typeof obj[key] === "object" && obj[key] !== null) {
            result[key] = deepClonePatchValue(obj[key]);
        } else {
            result[key] = obj[key];
        }
    }
    return result;
}

// Library uses the merge internally with hardcoded config, not user input
var defaultConfig = { theme: { color: "blue", size: 12 } };
var patchedConfig = deepClonePatchValue(defaultConfig);

// Another common pattern: TypeScript's __extends helper
var extendStatics = function(d, b) {
    for (var p in b) {
        if (typeof b[p] === "object" && b[p] !== null) {
            d[p] = extendStatics(d[p] || {}, b[p]);
        } else {
            d[p] = b[p];
        }
    }
    return d;
};

// Used only with internal class prototypes, never user input
extendStatics(Object.create(null), { method: function() {} });
