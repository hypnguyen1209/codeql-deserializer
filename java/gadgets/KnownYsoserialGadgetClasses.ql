/**
 * @name Known ysoserial gadget class present
 * @description A class declared in the target/source matches a class known to
 *              be used as a deserialization gadget by the ysoserial payload
 *              catalog (https://github.com/frohoff/ysoserial). Its presence is
 *              a strong signal that a deserialization sink in this codebase or
 *              its classpath is exploitable (CWE-502).
 * @kind problem
 * @id java/deserialization/known-gadget-class
 * @problem.severity warning
 * @security-severity 7.0
 * @precision high
 * @tag security
 * @tag external/cwe/cwe-502
 * @tags deserialization
 *      gadget
 *      ysoserial
 */

import java

/** Holds if `t` is one of the well-known ysoserial gadget source classes. */
predicate isKnownYsoserialGadgetClass(RefType t) {
  t.hasQualifiedName("org.apache.commons.collections.functors", [
    "InvokerTransformer", "ChainedTransformer", "ConstantTransformer",
    "InstantiateTransformer", "TransformedMap"
  ])
  or
  t.hasQualifiedName("org.apache.commons.collections.keyvalue", "TiedMapEntry")
  or
  t.hasQualifiedName("org.apache.commons.collections.map", ["LazyMap", "DefaultedMap"])
  or
  t.hasQualifiedName("org.apache.commons.collections4.functors", [
    "InvokerTransformer", "ChainedTransformer", "ConstantTransformer",
    "InstantiateTransformer"
  ])
  or
  t.hasQualifiedName("org.apache.commons.collections4.keyvalue", "TiedMapEntry")
  or
  t.hasQualifiedName("org.apache.commons.collections4.map", ["LazyMap", "DefaultedMap"])
  or
  t.hasQualifiedName("org.apache.commons.beanutils", ["BeanComparator", "PropertyUtilsBean"])
  or
  // JDK XSLT gadgets
  t.hasQualifiedName("com.sun.org.apache.xalan.internal.xsltc.trax", "TemplatesImpl")
  or
  t.hasQualifiedName("com.sun.org.apache.xalan.internal.xsltc.runtime", "AbstractTranslet")
  or
  t.hasQualifiedName("com.sun.org.apache.bcel.internal.util", "ClassLoader")
  or
  // Javassist
  t.hasQualifiedName("javassist.util.proxy", ["ProxyFactory", "ProxyObject", "RuntimeSupport"])
  or
  // Groovy
  t.hasQualifiedName("org.codehaus.groovy.runtime", [
    "ConvertedClosure", "MethodClosure", "ConversionHandler"
  ])
  or
  // Spring
  t.hasQualifiedName("org.springframework.beans.factory.config", "PropertyPathFactoryBean")
  or
  t.hasQualifiedName("org.springframework.transaction.jta", "JtaTransactionManager")
  or
  t.hasQualifiedName("org.springframework.aop.support", "AbstractBeanFactoryPointcutAdvisor")
  or
  t.hasQualifiedName("org.springframework.jndi", "JndiObjectFactoryBean")
  or
  // C3P0
  t.hasQualifiedName("com.mchange.v2.c3p0", "WrapperConnectionPoolDataSource")
  or
  // Hibernate
  t.hasQualifiedName("org.hibernate.property", "BasicPropertyAccessor")
  or
  // FileUpload
  t.hasQualifiedName("org.apache.commons.fileupload.disk", "DiskFileItem")
  or
  // Mozilla Rhino
  t.hasQualifiedName("org.mozilla.javascript", ["NativeJavaObject", "FunctionObject", "MemberBox"])
  or
  // JSON / fastjson
  t.hasQualifiedName("com.alibaba.fastjson", ["JSONArray", "JSONObject"])
  or
  // MyFaces
  t.hasQualifiedName("org.apache.myfaces.view.facelets.el", "ValueExpressionMethodExpression")
  or
  // Tomcat
  t.hasQualifiedName("org.apache.naming.resources", "ResourceRef")
  or
  // Commons configuration
  t.hasQualifiedName("org.apache.commons.configuration", "ConfigurationMap")
  or
  // Wicket
  t.hasQualifiedName("org.apache.wicket.util.link", "Link")
}

from RefType t
where isKnownYsoserialGadgetClass(t)
select t,
  "Known ysoserial gadget class: " + t.getName() +
    " is part of the ysoserial payload catalog and can weaponise a deserialization sink."
