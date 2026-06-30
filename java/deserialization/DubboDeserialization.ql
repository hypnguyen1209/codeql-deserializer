/**
 * @name Apache Dubbo unsafe deserialization chain
 * @description User-controlled data received by a Dubbo `Codec2.decodeBody(...)`
 *              method flows into an `ObjectInput.readXXX(...)` deserialization
 *              sink, enabling remote code execution via gadget chains (CWE-502).
 *              Looks for variants of CVE-2020-11995.
 * @kind path-problem
 * @id java/deserialization/dubbo-chain
 * @problem.severity error
 * @security-severity 9.8
 * @precision medium
 * @tag security
 * @tag external/cwe/cwe-502
 * @tags deserialization
 *      dubbo
 */

import java
import deserialization.DubboDeserializationModel
import DubboDeserializationFlow::PathGraph

from DubboDeserializationFlow::PathNode source, DubboDeserializationFlow::PathNode sink
where DubboDeserializationFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted data from a Dubbo codec is deserialized here, which can lead to remote code execution."
