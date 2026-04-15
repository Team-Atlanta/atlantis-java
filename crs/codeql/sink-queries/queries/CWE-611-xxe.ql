/**
 * @name XXE (XML External Entity) sinks
 * @description Reports all XXE sinks without dataflow tracking.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id java/cwe-611-xxe
 * @tags security
 *       external/cwe/cwe-611
 */

import java
import semmle.code.java.security.XmlParsers

from XmlParserCall parse
where not parse.isSafe()
select parse,
  "[" + parse.getEnclosingCallable().getDeclaringType().getQualifiedName() +
  ", " + parse.getEnclosingCallable().getName() +
  "] XXE sink: unsafe XML parsing"
