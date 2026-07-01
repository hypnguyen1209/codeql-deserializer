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

/** Every deserialization sink call: the official `codeql/java-all` set plus the
 *  extra framework sinks (Hessian/Kryo/MarshalledObject) modelled in #5. */
MethodCall deserializationSinkCall() {
  exists(JavaDeserializationSink s | result = s.getCall())
  or
  result instanceof ExtraDeserializationSinkCall
}

from MethodCall call
where call = deserializationSinkCall()
select call,
  "Deserialization sink: " + call.getMethod().getName() +
    "() deserializes data that may be attacker-controlled."
