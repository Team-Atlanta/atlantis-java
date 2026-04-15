/**
 * @name SQL injection sinks
 * @description Reports all SQL injection sinks without dataflow tracking.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id java/cwe-089-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import java
import semmle.code.java.security.QueryInjection

from QueryInjectionSink sink, Call call
where sink.asExpr() = call.getAnArgument()
select sink,
  "[" + sink.asExpr().getEnclosingCallable().getDeclaringType().getQualifiedName() +
  ", " + sink.asExpr().getEnclosingCallable().getName() +
  "] SQL injection sink"
