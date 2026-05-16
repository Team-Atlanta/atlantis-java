/**
 * @name Unsafe reflection sinks
 * @description Reports all reflection invocation sinks (Method.invoke and Constructor.newInstance) without dataflow tracking.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id java/cwe-470-unsafe-reflection
 * @tags security
 *       external/cwe/cwe-470
 */

import java
import semmle.code.java.dataflow.DataFlow

/**
 * A call to `java.lang.reflect.Method.invoke`.
 */
class MethodInvokeCall extends MethodCall {
  MethodInvokeCall() { this.getMethod().hasQualifiedName("java.lang.reflect", "Method", "invoke") }
}

/**
 * An expression that represents a hardcoded class (class literal or Class.forName with constant).
 */
predicate isHardcodedClass(Expr e) {
  // Class literal: Foo.class
  e instanceof TypeLiteral
  or
  // Class.forName("...") with constant first argument (class name)
  exists(MethodCall forName |
    forName.getMethod().hasQualifiedName("java.lang", "Class", "forName") and
    forName.getArgument(0) instanceof CompileTimeConstantExpr and
    e = forName
  )
}

/**
 * Check if the Constructor/Method was obtained from a hardcoded class.
 */
predicate flowsFromHardcodedClass(Expr qualifier) {
  // The qualifier is the Constructor or Method object
  // We need to find what it flows from
  exists(MethodCall getReflectionObject |
    // The qualifier flows from a call like getDeclaredConstructor() or getMethod()
    DataFlow::localExprFlow(getReflectionObject, qualifier) and
    // That call was made on a Class object
    exists(Expr classExpr |
      classExpr = getReflectionObject.getQualifier() and
      // That Class object flows from a hardcoded class
      exists(Expr source |
        isHardcodedClass(source) and
        DataFlow::localExprFlow(source, classExpr)
      )
    )
  )
  or
  // Direct case: qualifier itself is from a hardcoded class
  exists(Expr source |
    isHardcodedClass(source) and
    DataFlow::localExprFlow(source, qualifier)
  )
}

from MethodCall ma, string flag
where
  (
    ma.getMethod().getDeclaringType().getSourceDeclaration().hasQualifiedName("java.lang.reflect", "Constructor") and
    ma.getMethod().hasName("newInstance")
    or
    ma instanceof MethodInvokeCall
  ) and
  // Filter out various safe cases
  if ma.getQualifier() instanceof CompileTimeConstantExpr then
    flag = "[FILTERED: compile-time constant]"
  else if ma.getQualifier() instanceof NullLiteral then
    flag = "[FILTERED: null literal]"
  else if flowsFromHardcodedClass(ma.getQualifier()) then
    flag = "[FILTERED: hardcoded class]"
  else
    flag = ""
select ma,
  "[" + ma.getEnclosingCallable().getDeclaringType().getQualifiedName() +
  ", " + ma.getEnclosingCallable().getName() +
  "] Unsafe reflection call: " + ma.getMethod().getName() + " " + flag
