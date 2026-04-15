/**
 * @name Regex injection sinks
 * @description Reports all regex injection sinks without dataflow tracking.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id java/cwe-730-regex-injection
 * @tags security
 *       external/cwe/cwe-1333
 *       external/cwe/cwe-730
 *       external/cwe/cwe-400
 */

import java
import semmle.code.java.security.regexp.RegexInjection

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

from RegexInjectionSink sink, Call call, Expr arg, string flag
where
  sink.asExpr() = call.getAnArgument() and
  arg = sink.asExpr() and
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
select call,
  "[" + getActualDeclaringType(sink.asExpr().getEnclosingCallable()).getQualifiedName() +
  ", " + call.getEnclosingCallable().getName() +
  "] Regex injection sink " + flag
