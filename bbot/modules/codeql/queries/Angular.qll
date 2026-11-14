/**
 * AngularJS services, found by the name AngularJS injects them under.
 */

import javascript

/**
 * Gets the parameter AngularJS injects `service` into: named after it, or listed by name before the function, as
 * minified code has to.
 */
DataFlow::ParameterNode injected(string service) {
  service.matches("$%") and
  exists(DataFlow::FunctionNode fn, int i | result = fn.getParameter(i) |
    result.getName() = service
    or
    exists(ArrayExpr list |
      list.getElement(list.getSize() - 1).flow().getAFunctionValue() = fn and
      list.getElement(i).getStringValue() = service
    )
  )
}
