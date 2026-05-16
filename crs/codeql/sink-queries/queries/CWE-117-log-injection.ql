/**
 * @name Log injection sinks
 * @description Reports all logging sinks with user-controlled input without dataflow tracking. Includes Log4j (Log4Shell), SLF4J, java.util.logging, etc.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id java/cwe-117-log-injection
 * @tags security
 *       external/cwe/cwe-117
 *       external/cwe/cwe-020
 */

import java
import semmle.code.java.security.LogInjectionQuery
import semmle.code.java.security.LogInjection

from LogInjectionSink sink, Call call, string flag
where
  sink.asExpr() = call.getAnArgument() and
  // Check if there's flow from a source
  if not LogInjectionFlow::flow(_, sink) then
    flag = "[FILTERED: no flow from source]"
  else
    flag = ""
select call,
  "[" + call.getEnclosingCallable().getDeclaringType().getQualifiedName() +
  ", " + call.getEnclosingCallable().getName() +
  "] Log injection sink " + flag
