/**
 * Parts of the page's URL that an attacker controls by crafting the link.
 */

import javascript

/** Holds if `read` reads `name` from the page's location, e.g. `location.hash` or `window.location.hash`. */
predicate locationRead(DataFlow::PropRead read, string name) {
  read.getPropertyName() = name and
  (
    read.getBase().(DataFlow::PropRead).getPropertyName() = "location"
    or
    read.getBase().asExpr().(GlobalVarAccess).getName() = "location"
  )
}

/** Holds if `read` reads `name` from the document, e.g. `document.URL`. */
predicate documentRead(DataFlow::PropRead read, string name) {
  read.getPropertyName() = name and
  (
    read.getBase().(DataFlow::PropRead).getPropertyName() = "document"
    or
    read.getBase().asExpr().(GlobalVarAccess).getName() = "document"
  )
}

/** A call that URL-decodes its argument. */
private class UrlDecodeCall extends DataFlow::CallNode {
  UrlDecodeCall() { this.getCalleeName() in ["decodeURIComponent", "decodeURI", "unescape"] }
}

/** The browser percent-encodes the query string and path, so they're exploitable only once decoded. */
private module EncodedUrlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { locationRead(source, ["search", "pathname"]) }

  predicate isSink(DataFlow::Node sink) { sink = any(UrlDecodeCall call).getArgument(0) }
}

private module EncodedUrlFlow = TaintTracking::Global<EncodedUrlConfig>;

/** Holds if `source` is a part of the page's URL that an attacker controls. */
predicate isUrlSource(DataFlow::Node source) {
  // the browser doesn't encode the fragment, which href includes
  locationRead(source, ["hash", "href"])
  or
  documentRead(source, ["URL", "documentURI", "baseURI"])
  or
  // URLSearchParams.get() decodes
  exists(DataFlow::MethodCallNode call |
    call = source and
    call.getMethodName() = "get" and
    call.getReceiver().getALocalSource().(DataFlow::NewNode).getCalleeName() = "URLSearchParams"
  )
  or
  exists(UrlDecodeCall call | call = source and EncodedUrlFlow::flowTo(call.getArgument(0)))
}
