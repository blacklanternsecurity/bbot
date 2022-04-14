/*
* required polyfills
*/

/** IE9, IE10 and IE11 requires all of the following polyfills. **/
// import "core-js";
// import 'core-js/features/symbol'
// import 'core-js/features/object'
// import 'core-js/features/function'
// import 'core-js/features/parse-int'
// import 'core-js/features/parse-float'
// import 'core-js/features/number'
// import 'core-js/features/math'
// import 'core-js/features/string'
// import 'core-js/features/date'
// import 'core-js/features/array'
// import 'core-js/features/regexp'
// import 'core-js/features/map'
// import 'core-js/features/weak-map'
// import 'core-js/features/set'
// import 'core-js/features/set/map';

/** IE10 and IE11 requires the following for the Reflect API. */
// import 'core-js/features/reflect';

/** Evergreen browsers require these. **/
// Used for reflect-metadata in JIT. If you use AOT (and only Angular decorators), you can remove.
// import 'core-js/features/reflect'

// CustomEvent() constructor functionality in IE9, IE10, IE11
(function () {

  if ( typeof window.CustomEvent === "function" ) return false

  function CustomEvent ( event, params ) {
    params = params || { bubbles: false, cancelable: false, detail: undefined }
    var evt = document.createEvent( 'CustomEvent' )
    evt.initCustomEvent( event, params.bubbles, params.cancelable, params.detail )
    return evt
  }

  CustomEvent.prototype = window.Event.prototype

  window.CustomEvent = CustomEvent
})()

if (!Element.prototype.matches) {
  Element.prototype.matches =
    Element.prototype.msMatchesSelector ||
    Element.prototype.webkitMatchesSelector;
}

if (!Element.prototype.closest) {
  Element.prototype.closest = function(s) {
    var el = this;

    do {
      if (Element.prototype.matches.call(el, s)) return el;
      el = el.parentElement || el.parentNode;
    } while (el !== null && el.nodeType === 1);
    return null;
  };
}
