/**
 * @name Path traversal sinks
 * @description Reports all path traversal sinks without dataflow tracking.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id java/cwe-022-path-traversal
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.security.TaintedPathQuery

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

/**
 * A call that creates a temp file with constant arguments (safe from path traversal).
 */
predicate isSafeFileCreation(Expr e) {
  exists(MethodCall mc |
    mc = e and
    (
      // Files.createTempFile with constant arguments
      mc.getMethod().hasQualifiedName("java.nio.file", "Files", "createTempFile") and
      forall(Expr arg | arg = mc.getAnArgument() and arg.getType().(RefType).hasQualifiedName("java.lang", "String") |
        arg instanceof CompileTimeConstantExpr
      )
      or
      // File.createTempFile with constant arguments
      mc.getMethod().hasQualifiedName("java.io", "File", "createTempFile") and
      forall(Expr arg | arg = mc.getAnArgument() and arg.getType().(RefType).hasQualifiedName("java.lang", "String") |
        arg instanceof CompileTimeConstantExpr
      )
    )
  )
}

/**
 * Check if the expression flows from a safe file creation.
 */
predicate flowsFromSafeFileCreation(Expr e) {
  // Direct case: the expression itself is a safe file creation
  isSafeFileCreation(e)
  or
  // Variable case: check if a variable was assigned from safe file creation
  exists(Variable v, VarAccess va |
    va = e and
    v = va.getVariable() and
    flowsFromSafeFileCreation(v.getAnAssignedValue())
  )
  or
  // Method call on safe file: e.g., tmpFile.toFile() where tmpFile is safe
  exists(MethodCall mc |
    mc = e and
    flowsFromSafeFileCreation(mc.getQualifier())
  )
}

from TaintedPathSink sink, Call call, Expr arg, string flag
where
  sink.asExpr() = [call.getAnArgument(), call.getQualifier()] and
  arg = sink.asExpr() and
  if arg instanceof CompileTimeConstantExpr then
    flag = "[FILTERED: compile-time constant]"
  else if arg instanceof NullLiteral then
    flag = "[FILTERED: null literal]"
  else if arg.getType() instanceof PrimitiveType then
    flag = "[FILTERED: primitive type]"
  else if arg.getType().(RefType).hasQualifiedName("java.lang", ["Integer", "Long", "Boolean", "Double", "Float", "Short", "Byte"]) then
    flag = "[FILTERED: boxed primitive]"
  else if flowsFromSafeFileCreation(arg) then
    flag = "[FILTERED: safe file creation]"
  else
    flag = ""
select call,
  "[" + getActualDeclaringType(call.getEnclosingCallable()).getQualifiedName() +
  ", " + call.getEnclosingCallable().getName() +
  "] Path traversal sink " + flag
