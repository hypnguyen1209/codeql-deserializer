/**
 * @name Deserialization sink
 * @description This call performs deserialization (CWE-502). Even if no remote
 *              source is currently detected, every deserialization sink is a
 *              candidate gadget entry-point and should be reviewed.
 * @kind problem
 * @id java/deserialization/sink
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @tag security
 * @tag external/cwe/cwe-502
 * @tags deserialization
 *      sink
 */

import java
import deserialization.DeserializationSinkModel

from JavaDeserializationSink sink
select
  sink.getCall(),
  "Deserialization sink: " + sink.getCall().getMethod().getName() +
    "() deserializes data that may be attacker-controlled."
