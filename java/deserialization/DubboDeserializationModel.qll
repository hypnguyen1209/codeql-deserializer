/**
 * Apache Dubbo deserialization model (CWE-502).
 *
 * Models the Dubbo RPC deserialization attack surface used by CVE-2020-11995
 * and its variants: user input received by `Codec2.decodeBody(...)` (source)
 * flows into an `org.apache.dubbo.common.serialize.ObjectInput.readXXX(...)`
 * call (sink). Two extra taint steps are modelled so flow crosses Dubbo's
 * serialization SPI:
 *   - `Serialization.deserialize(url, InputStream)` : argument -> return value
 *   - `new <ObjectInputImpl>(InputStream)`            : constructor arg -> instance
 *
 * Adapted from the GreHack 2021 "CodeQL for Java: Unsafe deserialization in
 * Apache Dubbo" workshop by Alvaro Munoz (@pwntester).
 *   https://github.com/pwntester/codeql_grehack_workshop
 *
 * This is an example of how to extend the pack for a custom framework: instead
 * of only relying on the generic `UnsafeDeserializationSink`, it defines its own
 * source/sink for Dubbo's SPI.
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

/** Holds if `t` is the Dubbo `ObjectInput` SPI interface (new or legacy package). */
predicate isDubboObjectInputType(RefType t) {
  t.getASourceSupertype*().hasQualifiedName("org.apache.dubbo.common.serialize", "ObjectInput")
  or
  t.getASourceSupertype*().hasQualifiedName("com.alibaba.dubbo.common.serialize", "ObjectInput")
}

/** Holds if `t` is the Dubbo `Codec2` interface (new or legacy package). */
predicate isDubboCodecType(RefType t) {
  t.hasQualifiedName("org.apache.dubbo.remoting", "Codec2")
  or
  t.hasQualifiedName("com.alibaba.dubbo.remoting", "Codec2")
}

/** A `readXXX` call on an `ObjectInput` implementation. The deserialized value
 *  is the call's qualifier (the `ObjectInput` instance built from untrusted input). */
predicate isDubboDeserializationSink(DataFlow::Node sink) {
  exists(MethodCall read, Method m |
    m = read.getMethod() and
    m.getName().matches("read%") and
    isDubboObjectInputType(m.getDeclaringType()) and
    sink.asExpr() = read.getQualifier()
  )
}

/** The Dubbo `Codec2` interface. */
class DubboCodec extends RefType {
  DubboCodec() { isDubboCodecType(this) }
}

/** A `decodeBody` method on a subtype of `Codec2`. Its 2nd and 3rd parameters
 *  carry untrusted network input (InputStream / byte[]). */
class DubboCodecDecodeBody extends Method {
  DubboCodecDecodeBody() {
    this.getDeclaringType().getASupertype*() instanceof DubboCodec and
    this.hasName("decodeBody")
  }

  /** The untrusted parameters of a `decodeBody` implementation. */
  Parameter getAnUntrustedParameter() { result = this.getParameter([1, 2]) }
}

/** Taint-tracking configuration for the Dubbo deserialization chain. */
module DubboDeserializationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DubboCodecDecodeBody m | source.asParameter() = m.getAnUntrustedParameter())
  }

  predicate isSink(DataFlow::Node sink) {
    isDubboDeserializationSink(sink)
  }

  predicate isAdditionalFlowStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    // Dubbo's `Serialization.deserialize(url, InputStream)` helper: the
    // InputStream argument (index 1) taints the returned `ObjectInput`.
    exists(MethodCall ma |
      ma.getMethod().getName() = "deserialize" and
      ma.getMethod().getDeclaringType().getName() = "Serialization" and
      ma.getArgument(1) = fromNode.asExpr() and
      ma = toNode.asExpr()
    )
    or
    // Constructing an `ObjectInput` from an `InputStream`: the argument
    // taints the constructed instance (which is later used as the qualifier
    // of a `readXXX` call).
    exists(ConstructorCall cc |
      cc.getConstructedType().getASupertype*().hasQualifiedName("org.apache.dubbo.common.serialize", "ObjectInput") and
      cc.getArgument(0) = fromNode.asExpr() and
      cc = toNode.asExpr()
    )
  }
}

/** Global taint flow from Dubbo codec input to a Dubbo deserialization sink. */
module DubboDeserializationFlow = TaintTracking::Global<DubboDeserializationConfig>;
