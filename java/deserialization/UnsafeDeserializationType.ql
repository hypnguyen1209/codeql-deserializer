/**
 * @name Unsafe polymorphic deserialization type
 * @description Untrusted data controls the type descriptor (a `java.lang.Class`
 *              or `Type` argument) passed to a polymorphic deserializer such as
 *              Jackson, Jodd or Gson. This can instantiate attacker-chosen types
 *              and lead to remote code execution (CWE-502).
 * @kind path-problem
 * @id java/deserialization/unsafe-type
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @tag security
 * @tag external/cwe/cwe-502
 * @tags deserialization
 *      polymorphic
 */

import java
import deserialization.DeserializationSinkModel
import JavaUnsafeTypeFlow::PathGraph

from JavaUnsafeTypeFlow::PathNode source, JavaUnsafeTypeFlow::PathNode sink
where JavaUnsafeTypeFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted data controls the target type of a polymorphic deserializer."
