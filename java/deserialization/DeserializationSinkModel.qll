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

/** Source-to-sink taint flow from active threat-model sources (remote/user input)
 *  to deserialization sinks. Provided by `codeql/java-all`. */
module JavaDeserializationFlow = UnsafeDeserializationFlow;

/** Source-to-sink taint flow from remote input to a polymorphic type descriptor
 *  supplied to a deserializer (e.g. user-controlled `Class`/`Type` argument to
 *  Jackson/Jodd/Gson). Provided by `codeql/java-all`. */
module JavaUnsafeTypeFlow = UnsafeTypeFlow;
