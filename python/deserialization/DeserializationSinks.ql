/**
 * @name Deserialization sink
 * @description This call performs insecure decoding that may execute its input
 *              (CWE-502). Even if no remote source is currently detected, every
 *              such sink is a candidate entry-point for code execution and should
 *              be reviewed.
 * @kind problem
 * @id python/deserialization/sink
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @tag security
 * @tag external/cwe/cwe-502
 * @tags deserialization
 *      sink
 */

import python
import deserialization.DeserializationSinkModel

from PythonDeserializationSink sink
select sink, "Deserialization sink: this " + sink.getSinkFormat() +
  " decoding may execute attacker-controlled input."
