/**
 * @name Unsafe deserialization chain
 * @description Untrusted data flows from a remote/user-controlled source into an
 *              insecure decoding sink, enabling arbitrary code execution (CWE-502).
 * @kind path-problem
 * @id python/deserialization/unsafe-chain
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tag security
 * @tag external/cwe/cwe-502
 * @tags deserialization
 *      chain
 */

import python
import deserialization.DeserializationSinkModel
import PythonDeserializationFlow::PathGraph

from PythonDeserializationFlow::PathNode source, PythonDeserializationFlow::PathNode sink
where PythonDeserializationFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted data is deserialized here, which can lead to arbitrary code execution."
