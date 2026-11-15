// The regex jQuery 1.8 tests a $() string with: markup anywhere after text other than "#" or "<" is HTML
var rquickExpr = /^(?:[^#<]*(<[\w\W]+>)[^>]*$|#([\w\-]*)$)/;
