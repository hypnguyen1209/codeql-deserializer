/**
 * @name Unsafe Spring remote exporter deserialization
 * @description A Spring bean based on `RemoteInvocationSerializingExporter` or
 *              `HessianExporter` initializes a remoting endpoint that deserializes
 *              incoming data with `ObjectInputStream`. In the worst case this leads
 *              to remote code execution (CWE-502).
 * @kind problem
 * @id java/deserialization/spring-exporter
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @tag security
 * @tag external/cwe/cwe-502
 * @tags deserialization
 *      spring
 */

import java
import deserialization.SpringExporterModel

/** Holds if `type` is a Spring `@Configuration` (directly or via a meta-annotation). */
private predicate isConfiguration(RefType type) {
  type.hasAnnotation("org.springframework.context.annotation", "Configuration") or
  isConfigurationAnnotation(type.getAnAnnotation())
}

/** Holds if `annotation` is (or is meta-annotated as) a Spring `@Configuration`. */
private predicate isConfigurationAnnotation(Annotation annotation) {
  isConfiguration(annotation.getType()) or
  isConfigurationAnnotation(annotation.getType().getAnAnnotation())
}

/** A `@Bean` method in a `@Configuration` class that returns an unsafe Spring exporter. */
private class UnsafeExporterBeanMethod extends Method {
  string identifier;

  UnsafeExporterBeanMethod() {
    isRemoteInvocationSerializingExporter(this.getReturnType()) and
    isConfiguration(this.getDeclaringType()) and
    exists(Annotation a | this.getAnAnnotation() = a |
      a.getType().hasQualifiedName("org.springframework.context.annotation", "Bean") and
      if a.getValue("name") instanceof StringLiteral
      then identifier = a.getValue("name").(StringLiteral).getValue()
      else identifier = this.getName()
    )
  }

  /** The bean name (from `@Bean(name=...)` or the method name). */
  string getBeanIdentifier() { result = identifier }
}

from UnsafeExporterBeanMethod method
select method,
  "Unsafe deserialization in a Spring exporter bean '" + method.getBeanIdentifier() + "'."
