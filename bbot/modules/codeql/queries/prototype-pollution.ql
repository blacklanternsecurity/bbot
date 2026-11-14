/**
 * @name Client-side prototype pollution
 * @description Keys an attacker controls choose which object the page writes to, and reach Object.prototype through
 *              __proto__ or constructor.prototype, so every object in the page inherits the attacker's values.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision high
 * @id bbot/prototype-pollution
 * @tags security
 *       external/cwe/cwe-1321
 */

import javascript
import Inputs

final private class FinalPropRef = DataFlow::PropRef;

/** A property read or write whose property name is computed. */
class DynamicPropRef extends FinalPropRef {
  DynamicPropRef() { not exists(this.getPropertyName()) }
}

/** "__proto__" needs no encoding, so a key can come from input in any state. */
predicate key(DataFlow::Node node, InputState state) {
  node = any(DynamicPropRef ref).getPropertyNameExpr().flow() and exists(state)
}

predicate noBarrier(DataFlow::Node node) { none() }

module KeyFlow = InputFlow<key/2, noBarrier/1>;

/** Holds if the attacker chooses the property name of `ref`. */
predicate attackerKey(DynamicPropRef ref) { KeyFlow::flowTo(ref.getPropertyNameExpr().flow()) }

/** Holds if `cond` having `outcome` means variable `key` isn't `value`. */
predicate rulesOut(Expr cond, boolean outcome, Variable key, string value) {
  exists(EqualityTest test | test = cond |
    test.getAnOperand().(VarAccess).getVariable() = key and
    test.getAnOperand().getStringValue() = value and
    outcome = test.getPolarity().booleanNot()
  )
  or
  // ["__proto__", "constructor"].includes(key)
  exists(MethodCallExpr call, ArrayExpr list | call = cond |
    call.getMethodName() = "includes" and
    call.getArgument(0).(VarAccess).getVariable() = key and
    call.getReceiver().getUnderlyingValue() = list and
    list.getAnElement().getStringValue() = value and
    outcome = false
  )
  or
  outcome = false and rulesOut(cond.(LogOrExpr).getAnOperand(), outcome, key, value)
  or
  outcome = true and rulesOut(cond.(LogAndExpr).getAnOperand(), outcome, key, value)
  or
  rulesOut(cond.(LogNotExpr).getOperand(), outcome.booleanNot(), key, value)
  or
  rulesOut(cond.(ParExpr).getExpression(), outcome, key, value)
}

/** Holds if the code around `ref` makes sure its key isn't `value`. */
predicate guardedAgainst(DynamicPropRef ref, string value) {
  exists(ConditionGuardNode guard, Variable key |
    ref.getPropertyNameExpr().(VarAccess).getVariable() = key and
    rulesOut(guard.getTest(), guard.getOutcome(), key, value) and
    guard.dominates(ref.getPropertyNameExpr().getBasicBlock())
  )
}

/** Holds if `node` makes an empty object or array, a step on the way down rather than a value written. */
predicate emptyContainer(DataFlow::Node node) {
  node.asExpr().(ObjectExpr).getNumProperty() = 0
  or
  node.asExpr().(ArrayExpr).getSize() = 0
  or
  node = DataFlow::globalVarRef("Object").getAMemberCall("create")
  or
  emptyContainer(node.asExpr().(LogOrExpr).getRightOperand().flow())
}

/** Holds if `write` sets a property the attacker names, to a value rather than an empty object. */
predicate polluting(DynamicPropRef write) {
  write instanceof DataFlow::PropWrite and
  attackerKey(write) and
  not emptyContainer(write.(DataFlow::PropWrite).getRhs())
}

/** Holds if `test` is true only for plain objects, never for a function: by `typeof`, `toString()`, or a call. */
predicate plainObjectTest(Expr test, Variable v) {
  exists(EqualityTest typeOf |
    typeOf = test and
    typeOf.getAnOperand().(TypeofExpr).getOperand().(VarAccess).getVariable() = v and
    typeOf.getAnOperand().getStringValue() = "object"
  )
  or
  exists(EqualityTest tag |
    tag = test and
    tag.getAnOperand().(MethodCallExpr).getArgument(0).(VarAccess).getVariable() = v and
    tag.getAnOperand().getStringValue() = "[object Object]"
  )
  or
  plainObjectTest(test.(LogAndExpr).getAnOperand(), v)
  or
  plainObjectTest(test.getUnderlyingValue(), v) and not test = test.getUnderlyingValue()
  or
  // a helper whose result is such a test of its parameter
  exists(CallExpr call, Function check, Parameter p, int i | call = test |
    call.getArgument(i).(VarAccess).getVariable() = v and
    check = call.flow().(DataFlow::InvokeNode).getACallee() and
    p = check.getParameter(i) and
    plainObjectTest(check.getAReturnedExpr(), p.getVariable())
  )
}

/**
 * Holds if `node` is a use of a variable the code replaced with a new object unless it was a plain object, so it
 * can't be a function, or its constructor: `if (!isPlainObject(t)) t = {}`, or `isPlainObject(t) || (t = {})`.
 */
predicate plainOrReplaced(DataFlow::Node node) {
  exists(Variable v, Expr test, Assignment replace, ExprOrStmt check |
    plainObjectTest(test, v) and
    replace.getLhs().(VarAccess).getVariable() = v and
    (
      exists(IfStmt ifs | ifs = check |
        ifs.getCondition().getUnderlyingValue().(LogNotExpr).getOperand().getUnderlyingValue() = test and
        replace.getParent*() = ifs.getThen()
      )
      or
      exists(LogOrExpr either | either.getEnclosingStmt() = check |
        either.getLeftOperand().stripParens() = test and
        either.getRightOperand().stripParens() = replace
      )
    ) and
    node.asExpr().(VarAccess).getVariable() = v and
    check.getBasicBlock().(ReachableBasicBlock).strictlyDominates(node.asExpr().getBasicBlock())
  )
}

/** Objects with a prototype, made by the page. */
module OrdinaryObjectConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof DataFlow::ObjectLiteralNode or
    node instanceof DataFlow::ArrayCreationNode or
    node instanceof DataFlow::NewNode or
    node = DataFlow::globalVarRef("JSON").getAMemberCall("parse")
  }

  predicate isSink(DataFlow::Node node) { node = any(DynamicPropRef ref).getBase() }
}

module OrdinaryObjectFlow = DataFlow::Global<OrdinaryObjectConfig>;

/** Objects made without a prototype, by Object.create(null). */
module NullPrototypeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    exists(DataFlow::CallNode create | create = node |
      create = DataFlow::globalVarRef("Object").getAMemberCall("create") and
      create.getArgument(0).asExpr() instanceof NullLiteral
    )
  }

  predicate isSink(DataFlow::Node node) { node = any(DynamicPropRef ref).getBase() }
}

module NullPrototypeFlow = DataFlow::Global<NullPrototypeConfig>;

/** Holds if `ref`'s object is one made without a prototype, never an ordinary one, so it has none to reach. */
predicate onNullPrototype(DynamicPropRef ref) {
  NullPrototypeFlow::flowTo(ref.getBase()) and
  not OrdinaryObjectFlow::flowTo(ref.getBase())
}

private newtype TReach =
  /** The object may be a constructor function, reached by a key that may be "constructor". */
  TMaybeConstructor() or
  /** The object may be Object.prototype, reached by "__proto__", or "prototype" from a constructor. */
  TMaybePrototype()

class Reach extends TReach {
  string toString() {
    this = TMaybeConstructor() and result = "may be a constructor"
    or
    this = TMaybePrototype() and result = "may be Object.prototype"
  }
}

/** Objects the attacker's keys may have picked, as far as they go. */
module PrototypeConfig implements DataFlow::StateConfigSig {
  class FlowState = Reach;

  predicate isSource(DataFlow::Node node, FlowState state) {
    exists(DynamicPropRef read |
      read instanceof DataFlow::PropRead and
      node = read and
      attackerKey(read) and
      not onNullPrototype(read)
    |
      not guardedAgainst(read, "__proto__") and state = TMaybePrototype()
      or
      not guardedAgainst(read, "constructor") and state = TMaybeConstructor()
    )
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    // a constructor's prototype
    exists(DynamicPropRef read |
      read instanceof DataFlow::PropRead and
      attackerKey(read) and
      not guardedAgainst(read, "prototype") and
      node1 = read.getBase() and
      node2 = read and
      state1 = TMaybeConstructor() and
      state2 = TMaybePrototype()
    )
  }

  predicate isSink(DataFlow::Node node, FlowState state) {
    exists(DynamicPropRef write | polluting(write) and node = write.getBase()) and
    state = TMaybePrototype()
  }

  predicate isBarrier(DataFlow::Node node, FlowState state) {
    plainOrReplaced(node) and state = TMaybeConstructor()
  }
}

module PrototypeFlow = DataFlow::GlobalWithState<PrototypeConfig>;

from DynamicPropRef write, DataFlow::Node input
where
  polluting(write) and
  PrototypeFlow::flowTo(write.getBase()) and
  KeyFlow::flow(input, write.getPropertyNameExpr().flow())
select write, "Keys from $@ can make this write change Object.prototype.", input, inputName(input)
