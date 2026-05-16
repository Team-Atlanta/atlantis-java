/**
 * @name Script injection sinks (javax.script.ScriptEngine)
 * @description Reports all script engine injection sinks without dataflow tracking.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id java/cwe-094-script-injection
 * @tags security
 *       external/cwe/cwe-094
 */

import java

/** Copied from codeql's CWE-094/ScriptInjection.ql */
class ScriptEngineMethod extends Method {
  ScriptEngineMethod() {
    this.getDeclaringType().getAnAncestor().hasQualifiedName("javax.script", "ScriptEngine") and
    this.hasName("eval")
    or
    this.getDeclaringType().getAnAncestor().hasQualifiedName("javax.script", "Compilable") and
    this.hasName("compile")
    or
    this.getDeclaringType().getAnAncestor().hasQualifiedName("javax.script", "ScriptEngineFactory") and
    this.hasName(["getProgram", "getMethodCallSyntax"])
  }
}

from MethodCall ma
where ma.getMethod() instanceof ScriptEngineMethod
select ma,
  "[" + ma.getEnclosingCallable().getDeclaringType().getQualifiedName() +
  ", " + ma.getEnclosingCallable().getName() +
  "] Script engine injection sink: " + ma.getMethod().getName()
