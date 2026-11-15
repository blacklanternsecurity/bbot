/**
 * What an attacker can put into a page, and how much of it they control.
 *
 * Browsers percent-encode <, > and " everywhere in a URL, so until it's decoded, no part of one can open a tag. And
 * a whole URL starts with something the attacker doesn't choose (the origin, or the ? or # before the query or
 * fragment), so on its own it can't send the page anywhere. Each input carries an `InputState` saying which of those
 * still hold, and the sinks ask for the state they need.
 */

import javascript
import Angular

private newtype TInputState =
  /** A whole URL, or its query or fragment with the leading ? or #: encoded, with a start the attacker doesn't pick. */
  TUrl() or
  /** Part of a URL that starts where the attacker's text does, still encoded. */
  TUrlPart() or
  /** A whole URL, decoded. */
  TDecodedUrl() or
  /** Text the attacker controls entirely. */
  TControlled()

/** How much of a value an attacker controls. */
class InputState extends TInputState {
  string toString() {
    this = TUrl() and result = "url"
    or
    this = TUrlPart() and result = "url part"
    or
    this = TDecodedUrl() and result = "decoded url"
    or
    this = TControlled() and result = "controlled"
  }

  /** Holds if this text can hold any character, including <, > and ". */
  predicate isDecoded() { this = TDecodedUrl() or this = TControlled() }

  /** Holds if the attacker chooses this text's first characters. */
  predicate controlsStart() { this = TUrlPart() or this = TControlled() }
}

/** Gets the state of text the attacker controls entirely. */
InputState controlled() { result = TControlled() }

/** Gets a reference to another window: the one that framed or opened this page, or the top one. */
DataFlow::SourceNode otherWindow() {
  result = DataFlow::globalVarRef(["top", "parent", "opener"])
  or
  result =
    DataFlow::globalObjectRef().getAPropertyRead(["top", "parent", "opener", "contentWindow"])
  or
  result.(DataFlow::PropRead).getPropertyName() = "contentWindow"
}

private DataFlow::SourceNode locationObject(DataFlow::TypeTracker t) {
  t.start() and
  (
    result = DataFlow::globalVarRef("location")
    or
    // another window's, the document's, or a router's copy: win.location, this.props.location
    result.(DataFlow::PropRead).getPropertyName() = "location"
  )
  or
  exists(DataFlow::TypeTracker t2 | result = locationObject(t2).track(t2, t))
}

/** Gets a reference to a window's `Location` object, or an object standing in for it. */
DataFlow::SourceNode locationObject() { result = locationObject(DataFlow::TypeTracker::end()) }

private DataFlow::SourceNode pageLocation(DataFlow::TypeTracker t) {
  t.start() and
  (
    result = DataFlow::globalVarRef("location")
    or
    result = DOM::documentRef().getAPropertyRead("location")
  )
  or
  exists(DataFlow::TypeTracker t2 | result = pageLocation(t2).track(t2, t))
}

/** Gets a reference to this page's own `Location` object. */
DataFlow::SourceNode pageLocation() { result = pageLocation(DataFlow::TypeTracker::end()) }

private DataFlow::SourceNode domElement(DataFlow::TypeTracker t) {
  t.start() and
  (
    // looked up, created, or the document's own
    result =
      DOM::documentRef()
          .getAMethodCall([
              "getElementById", "querySelector", "createElement", "createElementNS",
              "elementFromPoint"
            ])
    or
    result =
      DOM::documentRef().getAPropertyRead(["body", "head", "documentElement", "activeElement"])
    or
    result = domElement().getAMethodCall(["querySelector", "closest", "cloneNode", "appendChild"])
    or
    result =
      domElement()
          .getAPropertyRead(["parentNode", "parentElement", "firstElementChild", "lastElementChild"])
    or
    // an item of a collection the page looks up
    exists(DataFlow::MethodCallNode all |
      all =
        [DOM::documentRef(), domElement()]
            .getAMethodCall([
                "querySelectorAll", "getElementsByTagName", "getElementsByClassName",
                "getElementsByName"
              ])
    |
      result = all.getAPropertyRead() or
      result = all.getAMethodCall("item") or
      result = all.getAMethodCall("forEach").getABoundCallbackParameter(0, 0)
    )
    or
    result = DataFlow::globalVarRef("event").getAPropertyRead(["target", "currentTarget"])
    or
    result =
      any(DataFlow::FunctionNode handler |
        handler = domElement().getAMethodCall("addEventListener").getArgument(1).getAFunctionValue()
      ).getParameter(0).getAPropertyRead(["target", "currentTarget"])
  )
  or
  exists(DataFlow::TypeTracker t2 | result = domElement(t2).track(t2, t))
}

/** Gets a reference to an element: one the page looks up, creates, or finds from another. */
DataFlow::SourceNode domElement() { result = domElement(DataFlow::TypeTracker::end()) }

/** Holds if `node` reads the page's path. */
predicate pathInput(DataFlow::Node node) { node = pageLocation().getAPropertyRead("pathname") }

/** Holds if `node` reads the page's URL, or a part of it, in `state`. */
predicate urlInput(DataFlow::Node node, InputState state) {
  state = TUrl() and
  (
    // the Location object becomes its href when used as a string
    node = locationObject()
    or
    node = locationObject().getAPropertyRead(["href", "search", "hash"])
    or
    node = DOM::documentRef().getAPropertyRead(["URL", "documentURI", "baseURI", "referrer"])
  )
  or
  // a path can start with the attacker's //evil.example. Only the page's own: routing code passes copies of it
  // around constantly, between its own functions.
  state = TUrlPart() and
  pathInput(node)
}

/** Gets a function that handles the messages other windows post to this one. */
private DataFlow::FunctionNode messageHandler() {
  exists(DataFlow::CallNode add |
    add = DataFlow::globalVarRef("addEventListener").getACall()
    or
    add = DataFlow::globalObjectRef().getAMethodCall("addEventListener")
  |
    add.getArgument(0).mayHaveStringValue("message") and
    result = add.getArgument(1).getAFunctionValue()
  )
  or
  result = DataFlow::globalObjectRef().getAPropertyWrite("onmessage").getRhs().getAFunctionValue()
  or
  exists(Assignment assign |
    assign.getLhs().(GlobalVarAccess).getName() = "onmessage" and
    result = assign.getRhs().flow().getAFunctionValue()
  )
  or
  // jQuery: $(window).on("message", handler)
  exists(JQuery::MethodCall on |
    on.getMethodName() = "on" and
    on.getArgument(0).mayHaveStringValue("message") and
    result = on.getLastArgument().getAFunctionValue()
  )
}

/** Gets the event a message handler is given, unwrapping jQuery's `originalEvent`. */
private DataFlow::SourceNode messageEvent(DataFlow::FunctionNode handler) {
  handler = messageHandler() and
  (
    result = handler.getParameter(0)
    or
    result = handler.getParameter(0).getAPropertyRead("originalEvent")
  )
}

/** Holds if `node` is a value the handler compares with something the attacker can't choose. */
private predicate strictlyCompared(DataFlow::Node node) {
  exists(EqualityTest test, Expr other |
    test.getAnOperand() = node.asExpr() and
    other = test.getAnOperand() and
    other != node.asExpr()
  |
    exists(other.getStringValue())
    or
    other.flow() = locationObject().getAPropertyRead("origin")
    or
    other.flow().(DataFlow::PropRead).getPropertyName() = "contentWindow"
  )
  or
  // a collection of origins; in a string, indexOf() and includes() would only find a substring
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = ["indexOf", "includes", "has"] and
    call.getArgument(0) = node and
    not exists(call.getReceiver().getStringValue())
  )
}

/**
 * Holds if `handler` checks where its messages come from: an exact comparison of the origin or the sending window.
 * A substring, prefix or pattern match of the origin isn't one, since another origin can contain it.
 */
private predicate checksSender(DataFlow::FunctionNode handler) {
  exists(DataFlow::PropRead read |
    read = messageEvent(handler).getAPropertyRead(["origin", "source"]) and
    strictlyCompared(read.getALocalUse())
  )
}

/** Holds if `node` is input the attacker controls entirely: window.name, or a message from any window. */
predicate controlledInput(DataFlow::Node node) {
  node = DataFlow::globalObjectRef().getAPropertyRead("name")
  or
  exists(DataFlow::FunctionNode handler |
    node = messageEvent(handler).getAPropertyRead("data") and
    not checksSender(handler)
  )
}

/** Holds if `node` is any input, in `state`. */
predicate attackerInput(DataFlow::Node node, InputState state) {
  urlInput(node, state)
  or
  controlledInput(node) and state = TControlled()
  or
  // AngularJS's $location: the whole URL, and its decoded parameters and fragment
  exists(DataFlow::MethodCallNode call |
    call = node and call = injected("$location").getAMethodCall(_)
  |
    call.getMethodName() = ["url", "absUrl"] and call.getNumArgument() = 0 and state = TUrl()
    or
    call.getMethodName() = "search" and call.getNumArgument() <= 1 and state = TControlled()
    or
    call.getMethodName() = "hash" and call.getNumArgument() = 0 and state = TControlled()
  )
}

/** Gets the source of the regular expression at `pattern`, if it's written out in the page. */
string regexSource(DataFlow::Node pattern) {
  result = pattern.getStringValue()
  or
  exists(DataFlow::RegExpCreationNode re | re.flowsTo(pattern) |
    // the literal's text, without its slashes and flags
    result = re.asExpr().(RegExpLiteral).getValue().regexpCapture("(?s)/(.*)/[a-z]*", 1)
    or
    result = re.(DataFlow::InvokeNode).getArgument(0).getStringValue()
  )
}

/**
 * Holds if `pattern` captures a parameter: a group after a ?, #, = or &, as in /[?&]next=([^&]*)/. A pattern built
 * at runtime, like getParameterByName's, is taken to.
 */
bindingset[pattern]
private predicate capturesParameter(DataFlow::Node pattern) {
  regexSource(pattern).regexpMatch("(?s).*[?#=&].*\\((?!\\?).*")
  or
  not exists(regexSource(pattern))
}

/**
 * Holds if `start` is where a "?" or "#" was found, so the substring from it starts with that "?" or "#": still a query
 * string or fragment as the URL has them.
 */
private predicate keepsDelimiter(DataFlow::Node start) {
  exists(DataFlow::MethodCallNode find | find = start.getALocalSource() |
    find.getMethodName() = ["indexOf", "lastIndexOf"] and
    find.getArgument(0).getStringValue() = ["?", "#"]
  )
}

/** Holds if `node2` is text taken out of the URL at `node1` from a point the attacker chooses. */
private predicate extractsUrlPart(DataFlow::Node node1, DataFlow::Node node2) {
  exists(DataFlow::MethodCallNode call | node1 = call.getReceiver() and node2 = call |
    // a substring that doesn't start at 0, or at a "?" or "#" it keeps
    call.getMethodName() = ["substring", "substr", "slice"] and
    not call.getArgument(0).getIntValue() = 0 and
    not keepsDelimiter(call.getArgument(0))
    or
    call.getMethodName() = "replace" and
    call.getArgument(0).getStringValue() = ["#", "?"] and
    call.getArgument(1).getStringValue() = ""
  )
  or
  // any piece of a split but the first
  exists(DataFlow::MethodCallNode split, DataFlow::PropRead piece |
    split.getMethodName() = "split" and
    node1 = split.getReceiver() and
    piece.getBase() = split and
    node2 = piece and
    not piece.getPropertyName() = "0"
  )
  or
  exists(DataFlow::MethodCallNode split, DataFlow::MethodCallNode last |
    split.getMethodName() = "split" and
    node1 = split.getReceiver() and
    last = split.getAMethodCall(["pop", "at"]) and
    node2 = last
  )
  or
  // a regular expression that captures a parameter out of the URL
  exists(DataFlow::MethodCallNode call, DataFlow::Node pattern |
    (
      call.getMethodName() = "exec" and node1 = call.getArgument(0) and pattern = call.getReceiver()
      or
      call.getMethodName() = ["match", "matchAll"] and
      node1 = call.getReceiver() and
      pattern = call.getArgument(0)
      or
      // replace(/.*next=([^&]*).*/, "$1") keeps only the group
      call.getMethodName() = "replace" and
      node1 = call.getReceiver() and
      pattern = call.getArgument(0) and
      call.getArgument(1).getStringValue().regexpMatch(".*\\$([1-9]|<\\w+>).*")
    ) and
    node2 = call and
    capturesParameter(pattern)
  )
}

/** Holds if `node2` is the text at `node1`, with its percent-encoding decoded. */
private predicate decodes(DataFlow::Node node1, DataFlow::Node node2) {
  exists(DataFlow::CallNode call |
    call = DataFlow::globalVarRef(["decodeURIComponent", "decodeURI", "unescape"]).getACall() and
    node1 = call.getArgument(0) and
    node2 = call
  )
}

/** Gets a reference to URLSearchParams built from `input`, or a URL's searchParams. */
private DataFlow::SourceNode searchParams(DataFlow::Node input) {
  exists(DataFlow::NewNode new |
    new = DataFlow::globalVarRef("URLSearchParams").getAnInstantiation() and
    input = new.getArgument(0) and
    result = new
  )
  or
  exists(DataFlow::NewNode url |
    url = DataFlow::globalVarRef("URL").getAnInstantiation() and
    input = url.getArgument(0) and
    result = url.getAPropertyRead("searchParams")
  )
}

/** Holds if `node2` gives decoded names or values from URLSearchParams over the text at `node1`. */
private predicate readsSearchParams(DataFlow::Node node1, DataFlow::Node node2) {
  exists(DataFlow::SourceNode params | params = searchParams(node1) |
    node2 = params.getAMethodCall(["get", "getAll", "entries", "values", "keys"])
    or
    node2 = params.getAMethodCall("forEach").getABoundCallbackParameter(0, [0, 1])
    or
    exists(DataFlow::CallNode fromEntries |
      fromEntries = DataFlow::globalVarRef("Object").getAMemberCall("fromEntries") and
      params.flowsTo(fromEntries.getAnArgument()) and
      node2 = fromEntries
    )
    or
    // for (const [name, value] of params)
    exists(ForOfStmt loop |
      params.flowsTo(loop.getIterationDomain().flow()) and
      node2 = DataFlow::lvalueNode(loop.getLValue().(BindingPattern).getABindingVarRef())
    )
  )
}

/**
 * Holds if text in `state1` at `node1` becomes text in `state2` at `node2`: a part taken out of a URL, a decoded URL,
 * or a URLSearchParams value.
 */
predicate inputStep(DataFlow::Node node1, InputState state1, DataFlow::Node node2, InputState state2) {
  extractsUrlPart(node1, node2) and
  (
    state1 = TUrl() and state2 = TUrlPart()
    or
    state1 = TDecodedUrl() and state2 = TControlled()
  )
  or
  decodes(node1, node2) and
  (
    state1 = TUrl() and state2 = TDecodedUrl()
    or
    state1 = TUrlPart() and state2 = TControlled()
  )
  or
  readsSearchParams(node1, node2) and
  (state1 = TUrl() or state1 = TUrlPart()) and
  state2 = TControlled()
  or
  // query string libraries: queryString.parse(location.search) decodes, queryString.extract() doesn't
  exists(DataFlow::MethodCallNode call |
    not call.getReceiver() =
      DataFlow::globalVarRef(["JSON", "Date", "Number", "Math", "Intl", "BigInt", "URL"]) and
    node1 = call.getArgument(0) and
    node2 = call
  |
    call.getMethodName() = "parse" and
    (state1 = TUrl() or state1 = TUrlPart()) and
    state2 = TControlled()
    or
    call.getMethodName() = "extract" and state1 = TUrl() and state2 = TUrlPart()
  )
  or
  // the server decodes what it echoes
  echoedByServer(node1, node2) and
  exists(state1) and
  state2 = TControlled()
}

/** Holds if `read` gets an item from `storage` (localStorage or sessionStorage) under `key`. */
private predicate storageRead(DataFlow::Node read, string storage, string key) {
  storage = ["localStorage", "sessionStorage"] and
  (
    exists(DataFlow::MethodCallNode call | call = read |
      call = DataFlow::globalVarRef(storage).getAMethodCall("getItem") and
      key = call.getArgument(0).getStringValue()
    )
    or
    read = DataFlow::globalVarRef(storage).getAPropertyRead(key) and
    not key = ["getItem", "setItem", "removeItem", "clear", "key", "length"]
  )
}

/** Holds if `value` is stored in `storage` under `key`. */
private predicate storageWrite(DataFlow::Node value, string storage, string key) {
  storage = ["localStorage", "sessionStorage"] and
  (
    exists(DataFlow::MethodCallNode call |
      call = DataFlow::globalVarRef(storage).getAMethodCall("setItem") and
      key = call.getArgument(0).getStringValue() and
      value = call.getArgument(1)
    )
    or
    exists(DataFlow::PropWrite write |
      write = DataFlow::globalVarRef(storage).getAPropertyWrite(key) and
      value = write.getRhs()
    )
  )
}

/** Gets an XMLHttpRequest the page makes, as a node referring to it. */
private DataFlow::SourceNode xhr() {
  result = DataFlow::globalVarRef("XMLHttpRequest").getAnInstantiation()
}

/** Gets a reference to `request` inside a handler for its response. */
private DataFlow::Node responseHandlerThis(DataFlow::SourceNode request) {
  exists(DataFlow::FunctionNode handler |
    handler =
      request.getAPropertyWrite(["onreadystatechange", "onload"]).getRhs().getAFunctionValue()
    or
    handler = request.getAMethodCall("addEventListener").getArgument(1).getAFunctionValue()
  |
    result = handler.getReceiver()
  )
}

/** Gets the name of the cookie `write` sets: the text before its first "=". */
private string cookieName(DataFlow::PropWrite write) {
  write = DOM::documentRef().getAPropertyWrite("cookie") and
  result =
    write
        .getRhs()
        .(StringOps::ConcatenationRoot)
        .getFirstLeaf()
        .getStringValue()
        .regexpCapture("\\s*([^=;\\s]+)\\s*=.*", 1)
}

/** Holds if `read` names cookie `name`, in a string or regular expression the page reads the cookies with. */
private predicate readsCookieNamed(DataFlow::Node read, string name) {
  exists(DataFlow::PropRead cookies, DataFlow::MethodCallNode call, Expr pattern |
    cookies = read and
    cookies = DOM::documentRef().getAPropertyRead("cookie") and
    cookies.flowsTo(call.getReceiver()) and
    pattern = call.getAnArgument().asExpr() and
    (
      pattern.getStringValue().regexpCapture("\\s*([^=;\\s]+)\\s*=?.*", 1) = name
      or
      pattern.(RegExpLiteral).getValue().regexpCapture("[^A-Za-z0-9_-]*([A-Za-z0-9_-]+)=.*", 1) =
        name
    )
  )
}

/**
 * Holds if a cookie the page sets at `node1` is read back at `node2`: by name, or by code that reads the cookies
 * without naming one.
 */
private predicate cookieStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(DataFlow::PropWrite write, string name |
    name = cookieName(write) and
    node1 = write.getRhs() and
    node2 = DOM::documentRef().getAPropertyRead("cookie") and
    (readsCookieNamed(node2, name) or not readsCookieNamed(node2, _))
  )
}

/** Holds if `node2` is the response to a request whose URL, at `node1`, carries input the server may echo. */
private predicate echoedByServer(DataFlow::Node node1, DataFlow::Node node2) {
  exists(DataFlow::SourceNode request |
    request = xhr() and
    node1 = request.getAMethodCall("open").getArgument(1) and
    node2 =
      [request, responseHandlerThis(request).getALocalSource()]
          .getAPropertyRead(["response", "responseText", "responseXML"])
  )
}

/** Holds if data the attacker put in at `node1` comes back out at `node2`: through storage or cookies, or an error. */
predicate secondOrderStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(string storage, string key |
    storageWrite(node1, storage, key) and
    storageRead(node2, storage, key)
  )
  or
  cookieStep(node1, node2)
  or
  // errors that quote what failed to parse (V8's JSON.parse, Firefox's URL), wherever they're caught
  exists(DataFlow::InvokeNode parse |
    parse = DataFlow::globalVarRef("JSON").getAMemberCall("parse")
    or
    parse = DataFlow::globalVarRef("URL").getAnInstantiation()
  |
    node1 = parse.getArgument(0) and
    node2 = parse.asExpr().getExceptionTarget()
  )
  or
  // an error built from the input, and its message once caught
  exists(DataFlow::NewNode error |
    error =
      DataFlow::globalVarRef(["Error", "TypeError", "RangeError", "SyntaxError"])
          .getAnInstantiation() and
    node1 = error.getArgument(0) and
    node2 = error
  )
  or
  exists(DataFlow::SourceNode caught |
    caught = any(Expr e).getExceptionTarget() and
    node1 = caught and
    node2 = caught.getAPropertyRead(["message", "stack"])
  )
}

/** Holds if `node2` is the parameter of a jQuery plugin the page defines, and `node1` what a call passes to it. */
private predicate jqueryPluginArgument(DataFlow::Node node1, DataFlow::Node node2) {
  exists(string name, DataFlow::FunctionNode plugin, JQuery::MethodCall call, int i |
    plugin =
      JQuery::dollar().getAPropertyRead("fn").getAPropertyWrite(name).getRhs().getAFunctionValue() and
    call.getMethodName() = name and
    node1 = call.getArgument(i) and
    node2 = plugin.getParameter(i)
  )
}

/**
 * Holds if `call` resolves to no function, and `fn` is a function the page registers under the name `call` uses, on
 * an object the analysis can't follow, as UMD wrappers and bundles do: `global.deparam = deparam`.
 */
private predicate registeredUnder(DataFlow::InvokeNode call, DataFlow::FunctionNode fn) {
  not exists(call.getACallee()) and
  exists(string name, DataFlow::PropWrite registration |
    (
      call = DataFlow::globalVarRef(name).getACall()
      or
      call = JQuery::dollar().getAMemberCall(name)
    ) and
    registration.getPropertyName() = name and
    fn = registration.getRhs().getAFunctionValue()
  )
}

/** Calls the library can't resolve, linked to the functions they reach: jQuery plugins and registered functions. */
private class UnresolvedCallStep extends DataFlow::AdditionalFlowStep {
  override predicate jumpStep(DataFlow::Node node1, DataFlow::Node node2) {
    jqueryPluginArgument(node1, node2)
    or
    exists(DataFlow::InvokeNode call, DataFlow::FunctionNode fn, int i |
      registeredUnder(call, fn) and
      node1 = call.getArgument(i) and
      node2 = fn.getParameter(i)
    )
  }
}

/** Holds if the page's code carries a value from `node1` to `node2` in a way the library doesn't follow. */
predicate pageCodeStep(DataFlow::Node node1, DataFlow::Node node2) {
  // an object's keys, unless it's one of the page's own, whose keys the page chose
  exists(ForInStmt loop |
    node1 = loop.getIterationDomain().flow() and
    not node1.getALocalSource() instanceof DataFlow::ObjectLiteralNode and
    node2 = DataFlow::lvalueNode(loop.getLValue().(BindingPattern).getABindingVarRef())
  )
  or
  exists(DataFlow::CallNode call |
    call =
      DataFlow::globalVarRef("Object").getAMemberCall(["keys", "entries", "getOwnPropertyNames"]) and
    node1 = call.getArgument(0) and
    not node1.getALocalSource() instanceof DataFlow::ObjectLiteralNode and
    node2 = call
  )
  or
  exists(DataFlow::CallNode call |
    call = DataFlow::globalVarRef("Object").getAMemberCall("fromEntries") and
    node1 = call.getArgument(0) and
    node2 = call
  )
}

/** Gets a few words naming the input at `node`, for a finding's message. */
string inputName(DataFlow::Node node) {
  attackerInput(node, _) and
  if node = DataFlow::globalObjectRef().getAPropertyRead("name")
  then result = "window.name"
  else
    if controlledInput(node)
    then result = "a message from another window"
    else result = "the page's URL"
}

/** A sink, given the state input must be in to reach it. */
signature predicate sinkSig(DataFlow::Node node, InputState state);

/** A barrier. */
signature predicate barrierSig(DataFlow::Node node);

/** Flow of attacker input, through the states above, to `sink`, unless `barrier` stops it. */
module InputFlow<sinkSig/2 sink, barrierSig/1 barrier> {
  private module Config implements DataFlow::StateConfigSig {
    class FlowState = InputState;

    predicate isSource(DataFlow::Node node, FlowState state) { attackerInput(node, state) }

    predicate isSink(DataFlow::Node node, FlowState state) { sink(node, state) }

    predicate isBarrier(DataFlow::Node node) { barrier(node) }

    predicate isAdditionalFlowStep(
      DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
    ) {
      inputStep(node1, state1, node2, state2)
    }

    predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
      secondOrderStep(node1, node2) or pageCodeStep(node1, node2)
    }
  }

  import TaintTracking::GlobalWithState<Config>
}
