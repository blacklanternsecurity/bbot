/**
 * What makes attacker input safe for a sink: escaping, encoding, conversion to a number, or a URL whose host is
 * already fixed.
 */

import javascript
import Inputs

/** Holds if `node` is a number made from its input. */
predicate numeric(DataFlow::Node node) {
  node = DataFlow::globalVarRef(["parseInt", "parseFloat", "Number", "isNaN"]).getACall()
  or
  node = DataFlow::globalVarRef("Math").getAMemberCall(_)
  or
  node.asExpr() instanceof PlusExpr
}

/** Holds if `node` is its input percent-encoded, which leaves no <, > or ", and no scheme. */
predicate encoded(DataFlow::Node node) {
  node = DataFlow::globalVarRef(["encodeURIComponent", "encodeURI", "escape"]).getACall()
}

/**
 * Holds if regular expression `source` matches a lone "<": "<", a class holding it like [<>], or a negated class
 * leaving it out like [^\w-]. One like <\w+ leaves "< " and "</" behind.
 */
bindingset[source]
predicate matchesLoneAngle(string source) {
  source.regexpMatch("<[+*]?")
  or
  exists(string body | body = source.regexpCapture("\\[([^\\]]*)\\][+*]?", 1) |
    not body.matches("^%") and body.matches("%<%")
    or
    body.matches("^%") and not body.matches("%<%")
  )
}

/** Holds if `call` replaces every < in its input with something else. */
private predicate escapesMarkup(DataFlow::MethodCallNode call) {
  exists(DataFlow::RegExpCreationNode pattern |
    call.getMethodName() = ["replace", "replaceAll"] and
    pattern.flowsTo(call.getArgument(0)) and
    pattern.isGlobal() and
    matchesLoneAngle(regexSource(pattern))
  ) and
  not call.getArgument(1).getStringValue().matches("%<%")
  or
  call.getMethodName() = "replaceAll" and
  call.getArgument(0).getStringValue() = "<" and
  not call.getArgument(1).getStringValue().matches("%<%")
}

/** Holds if `call` looks for a "<" in `checked`, finding nothing when there is none: /[<>]/.test(x), x.includes("<"). */
private predicate findsAngle(DataFlow::MethodCallNode call, DataFlow::Node checked) {
  call.getMethodName() = ["test", "exec"] and
  matchesLoneAngle(regexSource(call.getReceiver())) and
  checked = call.getArgument(0)
  or
  call.getMethodName() = "match" and
  matchesLoneAngle(regexSource(call.getArgument(0))) and
  checked = call.getReceiver()
  or
  call.getMethodName() = "includes" and
  call.getArgument(0).getStringValue() = "<" and
  checked = call.getReceiver()
}

/** A check that finds no "<" in a value, which can then hold no markup. */
private class AngleCheck extends DataFlow::Node {
  /** The outcome of this check that means there's no "<". */
  boolean absent;
  DataFlow::Node checked;

  AngleCheck() {
    findsAngle(this, checked) and absent = false
    or
    exists(EqualityTest test, DataFlow::MethodCallNode call | this.asExpr() = test |
      findsAngle(call, checked) and
      test.getAnOperand() = call.asExpr() and
      test.getAnOperand() instanceof NullLiteral and
      absent = test.getPolarity()
      or
      call.getMethodName() = "indexOf" and
      call.getArgument(0).getStringValue() = "<" and
      checked = call.getReceiver() and
      test.getAnOperand() = call.asExpr() and
      test.getAnOperand().getIntValue() = -1 and
      absent = test.getPolarity()
    )
  }

  predicate blocksExpr(boolean outcome, Expr e) { outcome = absent and e = checked.asExpr() }
}

/** A typeof check that rules out a string, which leaves nothing to hold markup or code: typeof x === "object". */
private class NotStringCheck extends DataFlow::ValueNode {
  override EqualityTest astNode;
  Expr checked;
  boolean notString;

  NotStringCheck() {
    exists(TypeofExpr typeOf, string type |
      astNode.getAnOperand() = typeOf and
      checked = typeOf.getOperand() and
      type = astNode.getAnOperand().getStringValue()
    |
      type != "string" and notString = astNode.getPolarity()
      or
      type = "string" and notString = astNode.getPolarity().booleanNot()
    )
  }

  predicate blocksExpr(boolean outcome, Expr e) { outcome = notString and e = checked }
}

/** Holds if `node` can't carry markup: sanitized, escaped, encoded or a number. */
predicate htmlBarrier(DataFlow::Node node) {
  encoded(node)
  or
  numeric(node)
  or
  escapesMarkup(node)
  or
  node = DataFlow::MakeBarrierGuard<AngleCheck>::getABarrierNode()
  or
  node = DataFlow::MakeBarrierGuard<NotStringCheck>::getABarrierNode()
  or
  // DOMPurify.sanitize() and its like are methods; a function merely named sanitize might be anything
  node.(DataFlow::MethodCallNode).getMethodName() = "sanitize"
  or
  node = DataFlow::globalVarRef(["filterXSS", "sanitizeHtml"]).getACall()
}

/** Holds if `node` can't make code: a number, or JSON, which is a literal. */
predicate codeBarrier(DataFlow::Node node) {
  numeric(node)
  or
  node = DataFlow::MakeBarrierGuard<NotStringCheck>::getABarrierNode()
  or
  node = DataFlow::globalVarRef("JSON").getAMemberCall("stringify")
}

/**
 * Holds if a URL starting with `prefix` points at a host the attacker can't change: the text after it is in the
 * query or fragment, or after the host's first slash, or a relative path's first segment. "/", "//", "https://" and
 * "https://example.com" all leave the host open (//evil.example, https://example.com@evil.example).
 */
bindingset[prefix]
private predicate fixesHost(string prefix) {
  prefix.regexpMatch("(?s).*([?#]|[^?#:/\\\\][/\\\\]).*|[/\\\\][^/\\\\].*")
}

/** Holds if `before` comes somewhere before `leaf` in the same concatenation. */
private predicate precedes(StringOps::ConcatenationLeaf before, StringOps::ConcatenationLeaf leaf) {
  before = leaf.getPreviousLeaf()
  or
  exists(StringOps::ConcatenationLeaf between |
    precedes(between, leaf) and before = between.getPreviousLeaf()
  )
}

/** Holds if `node` is concatenated after a ? or #, into a URL's query or fragment, where it can't change the path. */
predicate afterPath(DataFlow::Node node) {
  exists(StringOps::ConcatenationLeaf before |
    precedes(before, node) and
    before.getStringValue().regexpMatch("(?s).*[?#].*")
  )
}

/** Holds if `node` is concatenated after text that already fixes the URL's host. */
predicate afterFixedHost(DataFlow::Node node) {
  exists(StringOps::ConcatenationLeaf before |
    precedes(before, node) and
    fixesHost(before.getStringValue())
  )
}

/** A check that a URL starts with text that fixes its host. */
private class HostPrefixCheck extends StringOps::StartsWith {
  HostPrefixCheck() {
    fixesHost(this.getSubstring().getStringValue())
    or
    fixesHost(this.getSubstring().(StringOps::ConcatenationRoot).getFirstLeaf().getStringValue())
  }

  predicate blocksExpr(boolean outcome, Expr e) {
    outcome = this.getPolarity() and
    e = this.getBaseString().asExpr()
  }
}

/** A comparison of a URL's origin with the page's own, or a fixed one: url.origin === location.origin. */
private class OriginCheck extends DataFlow::ValueNode {
  override EqualityTest astNode;
  DataFlow::PropRead origin;

  OriginCheck() {
    origin.getPropertyName() = "origin" and
    astNode.getAnOperand() = origin.asExpr() and
    exists(Expr other | other = astNode.getAnOperand() and other != origin.asExpr() |
      exists(other.getStringValue())
      or
      other.flow() = locationObject().getAPropertyRead("origin")
    )
  }

  predicate blocksExpr(boolean outcome, Expr e) {
    outcome = astNode.getPolarity() and
    e = origin.getBase().asExpr()
  }
}

/** Holds if `node` holds a URL whose host the page has fixed, or checked. */
predicate urlBarrier(DataFlow::Node node) {
  encoded(node)
  or
  numeric(node)
  or
  node = DataFlow::MakeBarrierGuard<HostPrefixCheck>::getABarrierNode()
  or
  node = DataFlow::MakeBarrierGuard<OriginCheck>::getABarrierNode()
}

/**
 * Holds if a URL that starts with `value` can't be a javascript: URL: there's text in it, and it isn't, or isn't on its
 * way to, "javascript:".
 */
bindingset[value]
private predicate startsUrl(string value) {
  exists(string start | start = value.regexpReplaceAll("[\\s\\x00-\\x1f]", "").toLowerCase() |
    start != "" and
    not start.matches("javascript:%") and
    not "javascript:".matches(start + "%")
  )
}

/** Gets the text `node` is known to hold: a constant, or a variable set to one. */
private string knownValue(DataFlow::Node node) {
  result = node.getStringValue()
  or
  not exists(node.getStringValue()) and result = node.getALocalSource().getStringValue()
}

/**
 * Holds if `node` is concatenated after something that already starts the URL, so it can't make a javascript: URL:
 * text that does, or a value the page made, like a base URL, that isn't known to be empty.
 */
predicate afterUrlStart(DataFlow::Node node) {
  exists(StringOps::ConcatenationLeaf before | precedes(before, node) |
    forex(string value | value = knownValue(before) | startsUrl(value))
    or
    not exists(knownValue(before)) and
    not before.mayHaveStringValue("")
  )
}

/**
 * Gets what a check of `argument` checks: the argument itself, the variable it sets (check(url = input)), or the value
 * it makes a string ("" + url).
 */
private Expr checkedBy(Expr argument) {
  result = argument
  or
  result = argument.stripParens().(AssignExpr).getLhs()
  or
  result = argument.stripParens().(AssignExpr).getRhs()
  or
  result = argument.stripParens().(AddExpr).getAnOperand()
}

/**
 * Holds if regular expression `source` looks for a javascript: scheme, with or without anything between its letters:
 * /^javascript:/i, or React's /^[\u0000-\u001F ]*j[\r\n\t]*a.../i.
 */
bindingset[source]
private predicate findsJavascriptScheme(string source) {
  source
      .regexpMatch("(?is).*j.{0,12}a.{0,12}v.{0,12}a.{0,12}s.{0,12}c.{0,12}r.{0,12}i.{0,12}p.{0,12}t.{0,12}:.*")
}

/** A regular expression test for a javascript: scheme. Whichever way it comes out, the page acts on the answer. */
private class JavascriptSchemeCheck extends DataFlow::MethodCallNode {
  JavascriptSchemeCheck() {
    this.getMethodName() = "test" and
    findsJavascriptScheme(regexSource(this.getReceiver()))
  }

  predicate blocksExpr(boolean outcome, Expr e) {
    outcome = [true, false] and
    e = checkedBy(this.getArgument(0).asExpr())
  }
}

/**
 * Holds if `test` compares the protocol `protocol` reads with fixed ones, none of them javascript:.
 * url.protocol === "https:", ["http:", "https:"].includes(url.protocol).
 */
private predicate comparesProtocol(Expr test, DataFlow::PropRead protocol) {
  protocol.getPropertyName() = "protocol" and
  (
    exists(EqualityTest equality | equality = test |
      equality.getAnOperand() = protocol.asExpr() and
      equality.getAnOperand().getStringValue().toLowerCase() != "javascript:"
    )
    or
    exists(MethodCallExpr includes, ArrayExpr allowed | includes = test |
      includes.getMethodName() = "includes" and
      includes.getArgument(0) = protocol.asExpr() and
      includes.getReceiver().getUnderlyingValue() = allowed and
      forex(Expr scheme | scheme = allowed.getAnElement() |
        scheme.getStringValue().toLowerCase() != "javascript:"
      )
    )
  )
}

/** Holds if `protocol` is switched on, and each case is a fixed protocol other than javascript:. */
private predicate switchesOnProtocol(DataFlow::PropRead protocol) {
  protocol.getPropertyName() = "protocol" and
  exists(SwitchStmt switch | protocol.flowsToExpr(switch.getExpr()) |
    forex(Case case | case = switch.getACase() and exists(case.getExpr()) |
      case.getExpr().getStringValue().toLowerCase() != "javascript:"
    )
  )
}

/** Holds if `node` is a URL made from `value`: new URL(value), or new URL(value, base). */
private predicate urlFrom(DataFlow::Node node, DataFlow::Node value) {
  exists(DataFlow::NewNode url | url = DataFlow::globalVarRef("URL").getAnInstantiation() |
    url.flowsTo(node) and value = url.getArgument(0)
  )
}

/** A check of a URL's protocol against fixed ones: url.protocol === "https:", or of new URL(url).protocol. */
private class ProtocolCheck extends DataFlow::Node {
  DataFlow::PropRead protocol;
  boolean allowed;

  ProtocolCheck() {
    comparesProtocol(this.asExpr(), protocol) and
    if this.asExpr() instanceof EqualityTest
    then allowed = this.asExpr().(EqualityTest).getPolarity()
    else allowed = true
  }

  predicate blocksExpr(boolean outcome, Expr e) {
    outcome = allowed and
    (
      e = protocol.getBase().asExpr()
      or
      exists(DataFlow::Node value | urlFrom(protocol.getBase(), value) |
        e = checkedBy(value.asExpr())
      )
    )
  }
}

/** Holds if `node` is `f`'s first parameter, or a URL made from it. */
private predicate fromParameter(DataFlow::Node node, Function f) {
  exists(DataFlow::ParameterNode parameter |
    parameter = DataFlow::parameterNode(f.getParameter(0))
  |
    node.getALocalSource() = parameter
    or
    exists(DataFlow::Node value | urlFrom(node, value) and value.getALocalSource() = parameter)
  )
}

/**
 * Holds if `f` checks the protocol of the URL it's given against fixed ones, itself or through a function it passes
 * it to, and can return something falsy when it isn't one.
 */
private predicate validatesProtocol(Function f) {
  // null, false, undefined, or what a minifier makes of them (!1, void 0)
  f.getAReturnedExpr().analyze().getTheBooleanValue() = false and
  (
    exists(DataFlow::PropRead protocol |
      protocol.getPropertyName() = "protocol" and
      fromParameter(protocol.getBase(), f)
    |
      comparesProtocol(_, protocol) or switchesOnProtocol(protocol)
    )
    or
    exists(DataFlow::CallNode call |
      validatesProtocol(call.getACallee()) and
      fromParameter(call.getArgument(0), f)
    )
  )
}

/** A call to a function that checks a URL's protocol, given the URL: if (!isSafeUrl(url)) return. */
private class ProtocolValidation extends DataFlow::CallNode {
  ProtocolValidation() { validatesProtocol(this.getACallee()) }

  predicate blocksExpr(boolean outcome, Expr e) {
    outcome = true and e = checkedBy(this.getArgument(0).asExpr())
  }
}

/** Holds if `node` can't be a javascript: URL: something else starts the URL, or it was checked for one. */
predicate notJavascriptUrl(DataFlow::Node node) {
  afterUrlStart(node)
  or
  node = DataFlow::MakeBarrierGuard<JavascriptSchemeCheck>::getABarrierNode()
  or
  node = DataFlow::MakeBarrierGuard<ProtocolCheck>::getABarrierNode()
  or
  node = DataFlow::MakeBarrierGuard<ProtocolValidation>::getABarrierNode()
  or
  // check(url = input) && use(url), as a minifier writes a checked call's argument: a guard only covers later reads
  exists(DataFlow::CallNode check, SsaExplicitDefinition def |
    (check instanceof ProtocolValidation or check instanceof JavascriptSchemeCheck) and
    def.getDef() = check.getArgument(0).asExpr().stripParens() and
    node = DataFlow::ssaDefinitionNode(def)
  )
}
