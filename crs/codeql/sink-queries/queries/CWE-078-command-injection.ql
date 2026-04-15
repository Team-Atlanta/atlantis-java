/**
 * @name Command injection sinks
 * @description Reports all command injection sinks without dataflow tracking.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/cwe-078-command-injection
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.CommandLineQuery
import semmle.code.java.security.ExternalProcess

// Global dataflow configuration to track from command injection sinks to their usage
module CommandInjectionUsageConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(CommandInjectionSink sink, Call sinkCall |
      (
        sink.asExpr() = sinkCall.getAnArgument()
        or
        sink.(DataFlow::ImplicitVarargsArray).getCall() = sinkCall
      ) and
      source.asExpr() = sinkCall
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // Any call where the source flows to the qualifier or an argument
    exists(Call c | sink.asExpr() = [c.getQualifier(), c.getAnArgument()])
  }
}

module CommandInjectionUsageFlow = DataFlow::Global<CommandInjectionUsageConfig>;

from Call resultCall
where
  // Case 1: The original sink call itself (e.g., Runtime.exec(cmd))
  exists(CommandInjectionSink sink |
    sink.asExpr() = resultCall.getAnArgument()
    or
    sink.(DataFlow::ImplicitVarargsArray).getCall() = resultCall
  )
  or
  // Case 2: Subsequent usage where the sink flows to (e.g., procBuilder.start())
  CommandInjectionUsageFlow::flow(_, DataFlow::exprNode(resultCall.getQualifier()))
  or
  CommandInjectionUsageFlow::flow(_, DataFlow::exprNode(resultCall.getAnArgument()))
select resultCall,
  "[" + resultCall.getEnclosingCallable().getDeclaringType().getQualifiedName() +
  ", " + resultCall.getEnclosingCallable().getName() +
  "] Command injection sink"
