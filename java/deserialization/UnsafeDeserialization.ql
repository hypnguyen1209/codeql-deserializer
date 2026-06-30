/**
 * @name Unsafe deserialization chain
 * @description Untrusted data flows from a remote/user-controlled source into a
 *              deserialization sink, enabling remote code execution via gadget
 *              chains (CWE-502).
 * @kind path-problem
 * @id java/deserialization/unsafe-chain
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tag security
 * @tag external/cwe/cwe-502
 * @tags deserialization
 *      chain
 */

import java
import deserialization.DeserializationSinkModel
import JavaDeserializationFlow::PathGraph

from JavaDeserializationFlow::PathNode source, JavaDeserializationFlow::PathNode sink
where JavaDeserializationFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted data is deserialized here, which can lead to remote code execution."
