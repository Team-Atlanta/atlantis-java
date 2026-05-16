/**
 * @name Unsafe deserialization sinks (all sources)
 * @description Reports all unsafe deserialization sinks from both hardcoded patterns and external models without dataflow tracking.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/cwe-502-unsafe-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.security.UnsafeDeserializationQuery

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

// Models-as-data sinks
class DefaultUnsafeDeserializationSink extends DataFlow::Node {
  DefaultUnsafeDeserializationSink() { sinkNode(this, "unsafe-deserialization") }
}

from Expr sink, string msg
where
  // Hardcoded framework patterns (ObjectInputStream, XStream, Kryo, Jackson, etc.)
  (
    unsafeDeserialization(_, sink) and
    msg = "Unsafe deserialization sink (hardcoded pattern)"
  )
  or
  // External models (models-as-data)
  (
    sink = any(DefaultUnsafeDeserializationSink s).asExpr() and
    msg = "Unsafe deserialization sink (external model)"
  )
select sink,
  "[" + getActualDeclaringType(sink.getEnclosingCallable()).getQualifiedName() +
  ", " + sink.getEnclosingCallable().getName() +
  "] " + msg
