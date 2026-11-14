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
  exists(StringOps::ConcatenationLeaf between | precedes(between, leaf) and before = between.getPreviousLeaf())
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
