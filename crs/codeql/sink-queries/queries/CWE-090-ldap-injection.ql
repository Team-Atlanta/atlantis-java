/**
 * @name LDAP injection sinks
 * @description Reports all LDAP injection sinks without dataflow tracking.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/cwe-090-ldap-injection
 * @tags security
 *       external/cwe/cwe-090
 */

import java
import semmle.code.java.security.LdapInjection

from LdapInjectionSink sink, Call call
where sink.asExpr() = call.getAnArgument()
select call,
  "[" + call.getEnclosingCallable().getDeclaringType().getQualifiedName() +
  ", " + call.getEnclosingCallable().getName() +
  "] LDAP injection sink"
