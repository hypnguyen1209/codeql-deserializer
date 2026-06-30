/**
 * @name Unsafe deserialization in a remotely callable method (RMI)
 * @description If a registered remote object has a method that accepts a complex
 *              object, an attacker can abuse the unsafe deserialization mechanism
 *              used to pass parameters in RMI. In the worst case this leads to
 *              remote code execution (CWE-502).
 * @kind path-problem
 * @id java/deserialization/rmi
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @tag security
 * @tag external/cwe/cwe-502
 * @tags deserialization
 *      rmi
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Rmi
import BindingUnsafeRemoteObjectFlow::PathGraph

/**
 * A method that binds a name to a remote object.
 */
private class BindMethod extends Method {
  BindMethod() {
    (
      this.getDeclaringType().hasQualifiedName("java.rmi", "Naming") or
      this.getDeclaringType().hasQualifiedName("java.rmi.registry", "Registry")
    ) and
    this.hasName(["bind", "rebind"])
  }
}

/**
 * Holds if `type` has a vulnerable remote method (one that accepts a complex
 * object that Java will deserialize over RMI).
 */
private predicate hasVulnerableMethod(RefType type) {
  exists(RemoteCallableMethod m, Type parameterType |
    m.getDeclaringType() = type and parameterType = m.getAParamType()
  |
    not parameterType instanceof PrimitiveType and
    not parameterType instanceof TypeString and
    not parameterType instanceof TypeObjectInputStream
  )
}

/**
 * A taint-tracking configuration for unsafe remote objects that are vulnerable
 * to deserialization attacks.
 */
private module BindingUnsafeRemoteObjectConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ConstructorCall cc | cc = source.asExpr() |
      hasVulnerableMethod(cc.getConstructedType().getAnAncestor())
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall ma | ma.getArgument(1) = sink.asExpr() | ma.getMethod() instanceof BindMethod)
  }

  predicate isAdditionalFlowStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    exists(MethodCall ma, Method m | m = ma.getMethod() |
      m.getDeclaringType().hasQualifiedName("java.rmi.server", "UnicastRemoteObject") and
      m.hasName("exportObject") and
      not m.getParameterType([2, 4]).(RefType).hasQualifiedName("java.io", "ObjectInputFilter") and
      ma.getArgument(0) = fromNode.asExpr() and
      ma = toNode.asExpr()
    )
  }
}

private module BindingUnsafeRemoteObjectFlow =
  TaintTracking::Global<BindingUnsafeRemoteObjectConfig>;

from BindingUnsafeRemoteObjectFlow::PathNode source, BindingUnsafeRemoteObjectFlow::PathNode sink
where BindingUnsafeRemoteObjectFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Unsafe deserialization in a remote object."
