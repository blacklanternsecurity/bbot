/**
 * Where text in a page becomes markup, code, or the page's next location.
 */

import javascript
import Inputs

/** Gets an element the page creates with `document.createElement(tag)`. */
DataFlow::MethodCallNode createdElement(string tag) {
  result = DOM::documentRef().getAMethodCall("createElement") and
  tag = result.getArgument(0).getStringValue().toLowerCase()
}

/**
 * Holds if `element` is created by the page and never leaves the function that made it: it isn't added to the page,
 * passed anywhere, stored or returned, so setting its URL only parses that URL.
 */
private predicate detached(DataFlow::SourceNode element) {
  element = createdElement(_) and
  not exists(DataFlow::Node use | element.flowsTo(use) |
    use = any(DataFlow::InvokeNode call).getAnArgument()
    or
    use = any(DataFlow::PropWrite write).getRhs()
    or
    use.asExpr() = any(Function f).getAReturnedExpr()
  )
}

/** Holds if the script calls `click()` on `element`, following its link. */
private predicate clicked(DataFlow::SourceNode element) { exists(element.getAMethodCall("click")) }

/** Holds if `node` sets attribute `name` of `element`, by property, `setAttribute()` or jQuery. */
private predicate attributeWrite(DataFlow::SourceNode element, string name, DataFlow::Node node) {
  // as a property only on an element; plenty of other objects have an src or data
  exists(DataFlow::PropWrite write |
    write.getBase().getALocalSource() = element and
    (
      element = domElement()
      or
      // JSX for an element, like <a href={url}>, rather than a component
      element.asExpr().(JsxElement).getName().regexpMatch("[a-z].*")
    ) and
    name = write.getPropertyName().toLowerCase() and
    node = write.getRhs()
  )
  or
  exists(DataFlow::MethodCallNode call |
    call.getReceiver().getALocalSource() = element and
    call.getMethodName() = "setAttribute" and
    name = call.getArgument(0).getStringValue().toLowerCase() and
    node = call.getArgument(1)
  )
  or
  exists(DataFlow::MethodCallNode call |
    call.getReceiver().getALocalSource() = element and
    call.getMethodName() = "setAttributeNS" and
    name = call.getArgument(1).getStringValue().toLowerCase() and
    node = call.getArgument(2)
  )
  or
  exists(JQuery::MethodCall call |
    call.getReceiver().getALocalSource() = element and
    call.getMethodName() = ["attr", "prop"] and
    name = call.getArgument(0).getStringValue().toLowerCase() and
    node = call.getArgument(1)
  )
  or
  // jQuery's object forms: $(el).attr({ href: url }), $("<a>", { href: url })
  exists(JQuery::MethodCall call, DataFlow::PropWrite attribute |
    (
      call.getMethodName() = ["attr", "prop"] and
      call.getReceiver().getALocalSource() = element and
      attribute =
        call.getArgument(0).getALocalSource().(DataFlow::ObjectLiteralNode).getAPropertyWrite()
      or
      call.getMethodName() = "$" and
      call = element and
      attribute =
        call.getArgument(1).getALocalSource().(DataFlow::ObjectLiteralNode).getAPropertyWrite()
    ) and
    name = attribute.getPropertyName().toLowerCase() and
    node = attribute.getRhs()
  )
}

/**
 * Holds if `element` is a `tag` element: made by createElement, or by jQuery from markup like "<a>", or found by its
 * tag name, like getElementsByTagName("title")[0].
 */
private predicate knownTag(DataFlow::SourceNode element, string tag) {
  element = createdElement(tag)
  or
  exists(DataFlow::MethodCallNode lookup |
    tag = lookup.getArgument(0).getStringValue().toLowerCase() and
    tag.regexpMatch("[a-z][a-z0-9]*")
  |
    lookup.getMethodName() = ["getElementsByTagName", "querySelectorAll"] and
    (element = lookup.getAPropertyRead() or element = lookup.getAMethodCall("item"))
    or
    lookup.getMethodName() = "querySelector" and element = lookup
  )
  or
  exists(JQuery::MethodCall create | create = element and create.getMethodName() = "$" |
    tag =
      create
          .getArgument(0)
          .getStringValue()
          .regexpCapture("\\s*<([a-zA-Z0-9]+)[\\s/>].*", 1)
          .toLowerCase()
  )
}

/** The elements whose URL attribute can run a javascript: URL. */
private string urlRunningTag() {
  result = ["a", "area", "iframe", "frame", "form", "object", "embed", "base", "button", "input"]
}

/** Holds if `element` is a JSX component, whose props are only its own, not an element's attributes. */
private predicate jsxComponent(DataFlow::SourceNode element) {
  element.asExpr().(JsxElement).getName().regexpMatch("[A-Z].*")
}

/**
 * Holds if `node` is text a jQuery `$()` call reads as a selector, never HTML: it starts with fixed text other than "<",
 * like "#" or ".module-". jQuery before 1.9 read HTML anywhere in it (CVE-2012-6708, which retirejs reports).
 */
private predicate selectorText(DataFlow::Node node) {
  exists(StringOps::ConcatenationRoot root |
    root = node and
    root.getFirstLeaf().getStringValue().regexpMatch("\\s*[^\\s<].*")
  )
}

/** Gets a d3 selection: d3.select(...), and what its methods return as they chain. */
private DataFlow::SourceNode d3Selection() {
  result = DataFlow::globalVarRef("d3").getAMemberCall(["select", "selectAll", "create"])
  or
  result = d3Selection().getAMethodCall(_)
}

/** Elements whose content is never parsed as markup, so HTML written into one is only ever text, or a script's code. */
private string rawTextTag() {
  result =
    [
      "script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes", "noscript",
      "plaintext"
    ]
}

/** Holds if `element` is one whose content is never parsed as markup. */
private predicate rawText(DataFlow::SourceNode element) { knownTag(element, rawTextTag()) }

/** Holds if `node` is written into the page as HTML. */
predicate htmlSink(DataFlow::Node node) {
  exists(DataFlow::PropWrite write |
    write.getPropertyName() = ["innerHTML", "outerHTML", "srcdoc"] and
    node = write.getRhs() and
    // outerHTML is parsed where the element stands, so only innerHTML is safe in one whose content isn't markup
    not (write.getPropertyName() = "innerHTML" and rawText(write.getBase().getALocalSource()))
  )
  or
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = "insertAdjacentHTML" and node = call.getArgument(1)
    or
    call.getMethodName() = "createContextualFragment" and node = call.getArgument(0)
    or
    call.getMethodName() = "setHTMLUnsafe" and
    node = call.getArgument(0) and
    not rawText(call.getReceiver().getALocalSource())
    or
    call.getMethodName() = ["write", "writeln"] and
    (
      call.getReceiver().getALocalSource() = DOM::documentRef()
      or
      call.getReceiver().(DataFlow::PropRead).getPropertyName() = ["document", "contentDocument"]
    ) and
    node = call.getAnArgument()
  )
  or
  exists(JQuery::MethodCall call |
    call.interpretsArgumentAsHtml(node) and
    not (call.getMethodName() = "$" and selectorText(node))
  )
  or
  // d3: selection.html(value), or a function returning it
  exists(DataFlow::MethodCallNode call | call = d3Selection().getAMethodCall("html") |
    node = call.getArgument(0)
    or
    node = call.getArgument(0).getAFunctionValue().getAReturn()
  )
  or
  // React: { dangerouslySetInnerHTML: { __html: value } }, unless it's for an element whose content isn't markup
  exists(DataFlow::ObjectLiteralNode props, DataFlow::ObjectLiteralNode html |
    props.getAPropertyWrite("dangerouslySetInnerHTML").getRhs().getALocalSource() = html and
    node = html.getAPropertyWrite("__html").getRhs() and
    not exists(DataFlow::MethodCallNode create |
      create.getMethodName() = "createElement" and
      create.getArgument(0).getStringValue() = rawTextTag()
    |
      props.flowsTo(create.getArgument(1))
      or
      // copied first: Object.assign({}, props), or a compiled spread
      exists(DataFlow::InvokeNode copy |
        props.flowsTo(copy.getAnArgument()) and copy.flowsTo(create.getArgument(1))
      )
    )
  )
}

/** The attributes that make an element load or follow a URL, where a javascript: URL runs as code. */
private string urlAttribute() {
  result = ["href", "src", "action", "formaction", "data", "xlink:href"]
}

/**
 * Holds if `node` is the URL of a link, form, frame or object in the page, which runs a javascript: URL when it's
 * followed or loaded.
 */
predicate scriptUrlSink(DataFlow::Node node) {
  exists(DataFlow::SourceNode element |
    attributeWrite(element, urlAttribute(), node) and
    not detached(element) and
    // a script's URL is code from anywhere, a script injection
    not element = createdElement("script") and
    // not an element: the page's own location, a window, the page's data, or a component
    not element = [locationObject(), otherWindow(), DataFlow::globalObjectRef()] and
    not element instanceof DataFlow::ObjectLiteralNode and
    not jsxComponent(element) and
    // an element known not to follow or load a URL as code, like <img>
    not exists(string tag | knownTag(element, tag) and not tag = urlRunningTag())
  )
}

/** Holds if `node` becomes the location the page navigates to. */
predicate navigationSink(DataFlow::Node node) {
  // location = url
  node =
    [DOM::documentRef(), otherWindow(), DataFlow::globalObjectRef()]
        .getAPropertyWrite("location")
        .getRhs()
  or
  exists(Assignment assign |
    assign.getLhs().(GlobalVarAccess).getName() = "location" and
    node = assign.getRhs().flow()
  )
  or
  node = locationObject().getAPropertyWrite(["href", "host", "hostname", "protocol"]).getRhs()
  or
  node = locationObject().getAMethodCall(["assign", "replace"]).getArgument(0)
  or
  node =
    [DataFlow::globalVarRef("open"), otherWindow().getAPropertyRead("open")]
        .getACall()
        .getArgument(0)
  or
  // the Navigation API
  node = DataFlow::globalVarRef("navigation").getAMethodCall("navigate").getArgument(0)
  or
  // a link the script clicks
  exists(DataFlow::SourceNode element |
    clicked(element) and
    attributeWrite(element, "href", node)
  )
}

/**
 * Holds if `node` is in a JSON.parse polyfill (json2.js): a function installed as JSON.parse only when the browser has
 * none of its own, which no current browser lacks.
 */
private predicate inJsonParsePolyfill(DataFlow::Node node) {
  exists(DataFlow::PropWrite install, ConditionGuardNode guard, TypeofExpr check |
    install = DataFlow::globalVarRef("JSON").getAPropertyWrite("parse") and
    node.getContainer().getEnclosingContainer*() = install.getRhs().getAFunctionValue().getFunction() and
    check.getOperand().(PropAccess).getPropertyName() = "parse" and
    guard.getTest() = check.getParentExpr*() and
    guard.dominates(install.getBasicBlock())
  )
}

/** Holds if `node` is run as code. */
predicate codeSink(DataFlow::Node node) {
  node = DataFlow::globalVarRef("eval").getACall().getArgument(0) and not inJsonParsePolyfill(node)
  or
  node = DataFlow::globalVarRef("Function").getAnInvocation().getAnArgument() and not inJsonParsePolyfill(node)
  or
  exists(DataFlow::CallNode call |
    call =
      DataFlow::globalVarRef(["setTimeout", "setInterval", "setImmediate", "execScript"]).getACall() and
    node = call.getArgument(0) and
    not node.getALocalSource() instanceof DataFlow::FunctionNode
  )
  or
  node =
    createdElement("script")
        .getAPropertyWrite(["text", "textContent", "innerText", "innerHTML"])
        .getRhs()
  or
  node = JQuery::dollar().getAMemberCall("globalEval").getArgument(0)
  or
  // window[name](...): the attacker picks the function, unless a fixed prefix narrows the choice
  exists(DataFlow::CallNode call, DataFlow::PropRead callee |
    callee = call.getCalleeNode() and
    callee.getBase().getALocalSource() = DataFlow::globalObjectRef() and
    not exists(callee.getPropertyName()) and
    node = callee.getPropertyNameExpr().flow() and
    not exists(string prefix |
      prefix = node.(StringOps::ConcatenationRoot).getFirstLeaf().getStringValue() and prefix != ""
    )
  )
  or
  // an event handler written as an attribute: setAttribute("onclick", code)
  exists(DataFlow::MethodCallNode call, string name |
    (
      call.getMethodName() = ["setAttribute", "attr"] and
      name = call.getArgument(0).getStringValue().toLowerCase() and
      node = call.getArgument(1)
      or
      call.getMethodName() = "setAttributeNS" and
      name = call.getArgument(1).getStringValue().toLowerCase() and
      node = call.getArgument(2)
    ) and
    name.matches("on%")
  )
  or
  // AngularJS expressions
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() =
      ["$eval", "$evalAsync", "$apply", "$applyAsync", "$watch", "$watchCollection", "$watchGroup"] and
    node = call.getArgument(0)
  )
  or
  node = injected(["$compile", "$parse", "$interpolate"]).getACall().getArgument(0)
}

/** Holds if `node` is a URL the page loads and runs code from. */
predicate scriptLoadSink(DataFlow::Node node) {
  attributeWrite(createdElement("script"), "src", node)
  or
  node = JQuery::dollar().getAMemberCall("getScript").getArgument(0)
  or
  node = DataFlow::globalVarRef(["Worker", "SharedWorker"]).getAnInstantiation().getArgument(0)
  or
  node = DataFlow::globalVarRef("importScripts").getACall().getAnArgument()
  or
  node.asExpr() = any(DynamicImportExpr i).getSource()
}
