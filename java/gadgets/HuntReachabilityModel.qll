/**
 * Reachability-from-entry model for `find-gadget-deser.py`.
 *
 * Defines a combined set of *dangerous* calls (deserialization sinks + RCE
 * gadget actions) and call-graph reachability from a chosen start method. The
 * generated hunt query (one per run, with the `--start-class` baked in) uses
 * this to report chains `start -> ... -> dangerous sink`.
 */

import java
import semmle.code.java.security.UnsafeDeserializationQuery
import gadgets.GadgetModel

/**
 * A dangerous call: either an unsafe deserialization sink
 * (`ObjectInputStream.readObject`, XStream/Kryo/Jackson/Hessian/... per the
 * official `codeql/java-all` model) or an RCE gadget action
 * (`Runtime.exec`, `Method.invoke`, JNDI `lookup`, `Templates.newTransformer`,
 * `ClassLoader.loadClass`, `ScriptEngine.eval`, ...).
 */
class DangerousCall extends MethodCall {
  DangerousCall() {
    exists(UnsafeDeserializationSink s | this = s.getMethodCall())
    or
    this instanceof GadgetActionCall
  }

  /** Human-readable kind, e.g. "deserialization", "RCE:exec", "RCE:lookup". */
  string getDangerKind() {
    if exists(UnsafeDeserializationSink s | this = s.getMethodCall())
    then result = "deserialization"
    else result = "RCE:" + this.(GadgetActionCall).getActionName()
  }
}

/**
 * Holds if dangerous call `sink` is reachable from start method `start` through
 * the call graph (reflexive-transitive `calls*`, following virtual dispatch).
 */
predicate reachableDangerousFrom(Method start, DangerousCall sink) {
  start.calls*(sink.getCaller())
}
