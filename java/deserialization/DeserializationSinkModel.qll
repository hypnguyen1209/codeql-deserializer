/**
 * Deserialization sink & flow model for Java.
 *
 * This is the single extension point of the pack. It re-exports the
 * official `codeql/java-all` deserialization model (ObjectInputStream,
 * XStream, Kryo, SnakeYAML, Jackson polymorphic, Hessian, Jodd, Gson,
 * Fastjson, ...). Add new sinks here and every query below will pick them up.
 *
 * @see https://codeql.github.com/docs/codeql-language-guides/codeql-for-java/
 */

import java
import semmle.code.java.security.UnsafeDeserializationQuery

/** A call that performs unsafe deserialization (CWE-502). */
class JavaDeserializationSink extends UnsafeDeserializationSink {
  /** The underlying deserialization call, e.g. `ois.readObject()`. */
  MethodCall getCall() { result = this.getMethodCall() }
}

/**
 * Additional framework deserialization sink calls (#5) that the official
 * `codeql/java-all` model does not always cover: Caucho Hessian/Hessian2,
 * Esotericsoftware Kryo, and the RMI/JMX-remote `MarshalledObject.get()`
 * primitive. Surfaced by the `sink` triage query and treated as dangerous by the
 * find-gadget-deser reachability model.
 */
class ExtraDeserializationSinkCall extends MethodCall {
  ExtraDeserializationSinkCall() {
    exists(Method m | m = this.getMethod() |
      // Caucho Hessian / Hessian2
      m.getDeclaringType().getASupertype*().hasQualifiedName("com.caucho.hessian.io",
        ["Hessian2Input", "HessianInput", "AbstractHessianInput"]) and
        m.hasName(["readObject", "readObjectImpl"])
      or
      // Esotericsoftware Kryo (any Kryo instance, incl. those obtained from a Pool)
      m.getDeclaringType().getASupertype*().hasQualifiedName("com.esotericsoftware.kryo", "Kryo") and
        m.hasName(["readClassAndObject", "readObject", "readObjectOrNull"])
      or
      // RMI / JMX-remote: MarshalledObject.get() deserializes the wrapped bytes
      m.getDeclaringType().hasQualifiedName("java.rmi", "MarshalledObject") and m.hasName("get")
      or
      // javax.management.remote JMX: RMIConnection carries MarshalledObject params
      m.getDeclaringType().getASupertype*().hasQualifiedName("javax.management.remote.rmi", "RMIConnection") and
        m.hasName(["invoke", "setAttribute", "setAttributes", "createMBean"])
    )
  }
}

/** Source-to-sink taint flow from active threat-model sources (remote/user input)
 *  to deserialization sinks. Provided by `codeql/java-all`. */
module JavaDeserializationFlow = UnsafeDeserializationFlow;

/** Source-to-sink taint flow from remote input to a polymorphic type descriptor
 *  supplied to a deserializer (e.g. user-controlled `Class`/`Type` argument to
 *  Jackson/Jodd/Gson). Provided by `codeql/java-all`. */
module JavaUnsafeTypeFlow = UnsafeTypeFlow;
