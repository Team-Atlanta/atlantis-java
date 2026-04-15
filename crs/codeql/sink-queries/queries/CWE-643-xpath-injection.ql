/**
 * @name XPath injection sinks
 * @description Reports all XPath injection sinks without dataflow tracking.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/cwe-643-xpath-injection
 * @tags security
 *       external/cwe/cwe-643
 */

import java
import semmle.code.java.security.XPath

from XPathInjectionSink sink
select sink,
  "[" + sink.asExpr().getEnclosingCallable().getDeclaringType().getQualifiedName() +
  ", " + sink.asExpr().getEnclosingCallable().getName() +
  "] XPath injection sink"
