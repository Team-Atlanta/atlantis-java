/**
 * @name Server-side request forgery sinks
 * @description Reports all SSRF sinks without dataflow tracking.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id java/cwe-918-ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.security.RequestForgery

/**
 * Gets the actual declaring type, traversing up from anonymous classes.
 */
RefType getActualDeclaringType(Callable c) {
  exists(RefType declType | declType = c.getDeclaringType() |
    if declType instanceof AnonymousClass then
      result = declType.getEnclosingType()
    else
      result = declType
  )
}

from RequestForgerySink sink, Call sinkCall, Call resultCall, Expr arg, string flag
where
  // Find the call that contains the sink
  sink.asExpr() = [sinkCall.getAnArgument(), sinkCall.getQualifier()] and
  arg = sink.asExpr() and
  (
    // Case 1: Direct chained call - new URL(x).openStream()
    resultCall = sinkCall
    or
    // Case 2: Separate usage - URLConnection urlC = url.openConnection(); urlC.getInputStream()
    DataFlow::localExprFlow(sinkCall, resultCall.getQualifier())
  ) and
  if arg instanceof CompileTimeConstantExpr then
    flag = "[FILTERED: compile-time constant]"
  else if arg instanceof NullLiteral then
    flag = "[FILTERED: null literal]"
  else if arg.getType() instanceof PrimitiveType then
    flag = "[FILTERED: primitive type]"
  else if arg.getType().(RefType).hasQualifiedName("java.lang", ["Integer", "Long", "Boolean", "Double", "Float", "Short", "Byte"]) then
    flag = "[FILTERED: boxed primitive]"
  else
    flag = ""
select resultCall,
  "[" + getActualDeclaringType(resultCall.getEnclosingCallable()).getQualifiedName() +
  ", " + resultCall.getEnclosingCallable().getName() +
  "] Server-side request forgery sink " + flag
