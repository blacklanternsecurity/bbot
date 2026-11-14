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

/**
 * The input of `new URLSearchParams(input)`. It decodes every name and value read from it, and CodeQL models it
 * as a Map, so the input's taint reaches them however they're read (`get`, `forEach`, `for...of`, ...).
 */
private DataFlow::Node urlSearchParamsInput() {
  result = DataFlow::globalVarRef("URLSearchParams").getAnInstantiation().getArgument(0)
}

/** The browser percent-encodes the query string and path, so they're exploitable only once decoded. */
private module EncodedUrlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { locationRead(source, ["search", "pathname"]) }

  predicate isSink(DataFlow::Node sink) {
    sink = any(UrlDecodeCall call).getArgument(0) or sink = urlSearchParamsInput()
  }
}

private module EncodedUrlFlow = TaintTracking::Global<EncodedUrlConfig>;

/**
 * `Object.fromEntries()`, which CodeQL doesn't model. Each entry's value becomes a property of the object, and
 * a summary can't store into an unknown property, so the object is tainted instead.
 */
overlay[local?]
private class ObjectFromEntries extends DataFlow::SummarizedCallable::Range {
  ObjectFromEntries() { this = "Object.fromEntries" }

  override DataFlow::InvokeNode getACallSimple() {
    result = DataFlow::globalVarRef("Object").getAMemberCall("fromEntries")
  }

  override predicate propagatesFlow(string input, string output, boolean preservesValue) {
    input = "Argument[0]." + ["MapValue", "ArrayElement.Member[1]", "IteratorElement.Member[1]"] and
    output = "ReturnValue" and
    preservesValue = false
  }
}

/** A `URLSearchParams`, constructed or a URL's `searchParams`. */
private DataFlow::SourceNode urlSearchParams(DataFlow::TypeTracker t) {
  t.start() and
  (
    result = DataFlow::globalVarRef("URLSearchParams").getAnInstantiation()
    or
    result.(DataFlow::PropRead).getPropertyName() = "searchParams"
  )
  or
  exists(DataFlow::TypeTracker t2 | result = urlSearchParams(t2).track(t2, t))
}

/** Holds if `node` turns a `URLSearchParams` back into a string, which percent-encodes its names and values again. */
predicate isUrlBarrier(DataFlow::Node node) {
  exists(DataFlow::SourceNode params | params = urlSearchParams(DataFlow::TypeTracker::end()) |
    node = params.getAMethodCall("toString")
    or
    params.flowsTo(node) and node instanceof StringOps::ConcatenationOperand
  )
}

/** Holds if `source` is a part of the page's URL that an attacker controls. */
predicate isUrlSource(DataFlow::Node source) {
  // the browser doesn't encode the fragment, which href includes
  locationRead(source, ["hash", "href"])
  or
  documentRead(source, ["URL", "documentURI", "baseURI"])
  or
  exists(UrlDecodeCall call | call = source and EncodedUrlFlow::flowTo(call.getArgument(0)))
  or
  source = urlSearchParamsInput() and EncodedUrlFlow::flowTo(source)
}
