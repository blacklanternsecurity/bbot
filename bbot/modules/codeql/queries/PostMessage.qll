/**
 * Messages a page posts to any origin, and what's in them.
 */

import javascript
import Inputs

/** A call that posts a message whichever window receives it can read: postMessage(data, "*"). */
class WildcardPostMessage extends DataFlow::MethodCallNode {
  WildcardPostMessage() {
    this.getMethodName() = "postMessage" and
    this.getArgument(1).getStringValue() = "*"
  }
}

/** Holds if `node` is in the message `call` posts: the data, a property or element of it, or what was serialized into it. */
predicate messageContent(WildcardPostMessage call, DataFlow::Node node) {
  node = call.getArgument(0)
  or
  exists(DataFlow::Node outer | messageContent(call, outer) |
    node = outer.getALocalSource().(DataFlow::ObjectLiteralNode).getAPropertyWrite().getRhs()
    or
    node = outer.getALocalSource().(DataFlow::ArrayCreationNode).getAnElement()
    or
    exists(DataFlow::CallNode stringify |
      stringify = DataFlow::globalVarRef("JSON").getAMemberCall("stringify") and
      stringify.flowsTo(outer) and
      node = stringify.getArgument(0)
    )
  )
}

/** Holds if `node` holds something a page keeps from other origins: its URL, cookies or storage. */
predicate sensitive(DataFlow::Node node) {
  urlInput(node, _) and
  not node = DOM::documentRef().getAPropertyRead("referrer")
  or
  node = DOM::documentRef().getAPropertyRead("cookie")
  or
  exists(string storage | storage = ["localStorage", "sessionStorage"] |
    node = DataFlow::globalVarRef(storage).getAMethodCall("getItem")
    or
    node = DataFlow::globalVarRef(storage).getAPropertyRead(_) and
    not node = DataFlow::globalVarRef(storage).getAPropertyRead(["getItem", "setItem", "removeItem", "clear", "key", "length"])
  )
}

module LeakConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { sensitive(node) }

  predicate isSink(DataFlow::Node node) { messageContent(_, node) }

  predicate isBarrier(DataFlow::Node node) { sharedCode(node) }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) { iterationStep(node1, node2) }
}

module LeakFlow = TaintTracking::Global<LeakConfig>;

/** Holds if `call` posts something sensitive to any origin. */
predicate leaks(WildcardPostMessage call, DataFlow::Node source) {
  exists(DataFlow::Node node | messageContent(call, node) and LeakFlow::flow(source, node))
}

/** Holds if `node` is a constant, the same whoever loads the page. */
private predicate constant(DataFlow::Node node) {
  exists(node.getStringValue())
  or
  node.asExpr() instanceof Literal
  or
  node.asExpr() instanceof BooleanLiteral
  or
  node.asExpr().(LogNotExpr).getOperand() instanceof NumberLiteral
  or
  node.asExpr().(VarAccess).getName() = "undefined"
}

/** Holds if `call` posts something besides constants, at `node`. */
predicate postsData(WildcardPostMessage call, DataFlow::Node node) {
  messageContent(call, node) and
  not constant(node) and
  not node.getALocalSource() instanceof DataFlow::ObjectLiteralNode and
  not node.getALocalSource() instanceof DataFlow::ArrayCreationNode and
  not node.getALocalSource() = DataFlow::globalVarRef("JSON").getAMemberCall("stringify")
}
