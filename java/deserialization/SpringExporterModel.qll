/**
 * Spring remote-service exporter deserialization model (CWE-502).
 *
 * Spring remoting exporters (HTTP Invoker / RMI / Hessian / Burlap) expose
 * endpoints that deserialize incoming request bodies with `ObjectInputStream`.
 * A bean based on `RemoteInvocationSerializingExporter` or `HessianExporter`
 * is therefore a deserialization sink reachable over the network.
 *
 * Adapted from GitHubSecurityLab/CodeQL-Community-Packs
 * (`java/src/security/CWE-502/UnsafeSpringExporterLib.qll`).
 */

import java

/** Holds if `type` is a Spring remote exporter that deserializes request bodies. */
predicate isRemoteInvocationSerializingExporter(RefType type) {
  type.getAnAncestor()
      .hasQualifiedName("org.springframework.remoting.rmi",
        ["RemoteInvocationSerializingExporter", "RmiBasedExporter"])
  or
  type.getAnAncestor().hasQualifiedName("org.springframework.remoting.caucho", "HessianExporter")
}
