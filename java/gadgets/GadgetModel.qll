/**
 * ysoserial-style deserialization gadget model (CWE-502).
 *
 * ysoserial (https://github.com/frohoff/ysoserial) weaponises Java native
 * deserialization by chaining a *gadget entry point* (a `Serializable` type's
 * `readObject`/`readResolve`/`readExternal` callback, or a method invoked
 * through a proxy/comparator/map such as `InvocationHandler.invoke`) to an
 * *action* (RCE primitive: `Runtime.exec`, `ProcessBuilder.start`,
 * `Method.invoke`, `Class.forName`+`newInstance`, `ClassLoader.loadClass`,
 * `ScriptEngine.eval`, JNDI `lookup`, `Templates.newTransformer`, ...).
 *
 * This file defines those concepts plus the call-graph reachability that ties
 * entry/link to action, and the ysoserial known-gadget catalog. The gadget
 * hunting queries consume them.
 *
 * All entry/link/catalog predicates are restricted to target *source* code
 * (`.fromSource()`) so JDK/library internals are not reported.
 */

import java

/** Holds if `t` is (transitively) `java.io.Serializable`. */
predicate isSerializableType(RefType t) {
  t.getASupertype*().hasQualifiedName("java.io", "Serializable")
}

/**
 * A call to an RCE/sensitive primitive that a deserialization gadget may
 * eventually trigger. This is the "action" end of a ysoserial chain.
 */
class GadgetActionCall extends MethodCall {
  GadgetActionCall() {
    exists(Method m | m = this.getMethod() |
      // Runtime.exec
      m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and m.hasName("exec")
      or
      // ProcessBuilder.start
      m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and m.hasName("start")
      or
      // Reflection: Method.invoke
      m.getDeclaringType().getASupertype*().hasQualifiedName("java.lang.reflect", "Method") and
      m.hasName("invoke")
      or
      // Reflection: Class.forName / Class.newInstance
      m.getDeclaringType().getASupertype*().hasQualifiedName("java.lang", "Class") and
      m.hasName(["forName", "newInstance"])
      or
      // Reflection: Constructor.newInstance
      m.getDeclaringType().getASupertype*().hasQualifiedName("java.lang.reflect", "Constructor") and
      m.hasName("newInstance")
      or
      // ClassLoader.loadClass
      m.getDeclaringType().getASupertype*().hasQualifiedName("java.lang", "ClassLoader") and
      m.hasName("loadClass")
      or
      // Scripting: ScriptEngine.eval
      m.getDeclaringType().getASupertype*().hasQualifiedName("javax.script", "ScriptEngine") and
      m.hasName("eval")
      or
      // JNDI: InitialContext.lookup/bind/rebind
      m.getDeclaringType().getASupertype*().hasQualifiedName("javax.naming", "InitialContext") and
      m.hasName(["lookup", "bind", "rebind"])
      or
      // XSLT: Templates.newTransformer (covers com.sun...xsltc.trax.TemplatesImpl)
      m.hasName("newTransformer") and
      m.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.transform", "Templates")
      or
      // XSLT: TransformerFactory.newTransformer
      m.getDeclaringType().hasQualifiedName("javax.xml.transform", "TransformerFactory") and
      m.hasName("newTransformer")
      or
      // URL.openConnection (SSRF / remote class-load setup)
      m.getDeclaringType().hasQualifiedName("java.net", "URL") and m.hasName("openConnection")
      or
      // URLClassLoader.newInstance / loadClass
      m.getDeclaringType().hasQualifiedName("java.net", "URLClassLoader") and
      m.hasName(["newInstance", "loadClass"])
    )
  }

  /** Name of the action primitive, e.g. "exec", "invoke", "lookup". */
  string getActionName() { result = this.getMethod().getName() }

  /** Severity band for the action primitive, used to rank hunting results. */
  string getActionSeverity() {
    if this.getActionName() = ["exec", "start", "lookup", "eval", "loadClass"]
    then result = "critical"
    else (
      if this.getActionName() = ["invoke", "newInstance", "forName", "newTransformer", "openConnection"]
      then result = "high"
      else result = "medium"
    )
  }
}

/** Holds if `method` is a deserialization callback (entry point) in source. */
private predicate isDeserializationCallback(Method method) {
  method.fromSource() and
  isSerializableType(method.getDeclaringType()) and
  (
    // private void readObject(ObjectInputStream)
    method.hasName("readObject") and method.getNumberOfParameters() = 1 and
    method.getParameter(0).getType().(RefType).getASupertype*()
      .hasQualifiedName("java.io", "ObjectInputStream")
    or
    // void readObjectNoData()
    method.hasName("readObjectNoData") and method.getNumberOfParameters() = 0
    or
    // Object readResolve()
    method.hasName("readResolve") and method.getNumberOfParameters() = 0
    or
    // void readExternal(ObjectInput)
    method.hasName("readExternal") and method.getNumberOfParameters() = 1 and
    method.getParameter(0).getType().(RefType).getASupertype*().hasQualifiedName("java.io", "ObjectInput")
  )
}

/**
 * A deserialization gadget *entry point*: a `Serializable`/`Externalizable`
 * type's `readObject`/`readResolve`/`readExternal`/`readObjectNoData` callback.
 * Invoked by `ObjectInputStream.readObject()` on attacker-controlled data.
 */
class GadgetEntryPoint extends Method {
  GadgetEntryPoint() { isDeserializationCallback(this) }
}

/**
 * A *gadget link* method: an intermediate method ysoserial chains through —
 * `InvocationHandler.invoke`, `Comparator.compare`/`Comparable.compareTo`,
 * `Map.get/put/entrySet/containsKey`, and `Object.equals/hashCode/toString`
 * on serializable types. The deserialization machinery can trigger these
 * (proxy `equals`/`hashCode`, `HashMap`/`TreeMap` insertion, etc.).
 */
class GadgetLinkMethod extends Method {
  GadgetLinkMethod() {
    this.fromSource() and
    (
      this.hasName("invoke") and
      this.getDeclaringType().getASupertype*().getSourceDeclaration().hasQualifiedName("java.lang.reflect", "InvocationHandler")
      or
      this.hasName(["compare", "compareTo"]) and
      (
        this.getDeclaringType().getASupertype*().getSourceDeclaration().hasQualifiedName("java.util", "Comparator")
        or
        this.getDeclaringType().getASupertype*().getSourceDeclaration().hasQualifiedName("java.lang", "Comparable")
      )
      or
      this.hasName(["get", "put", "entrySet", "containsKey"]) and
      this.getDeclaringType().getASupertype*().getSourceDeclaration().hasQualifiedName("java.util", "Map")
      or
      this.hasName(["equals", "hashCode", "toString"]) and isSerializableType(this.getDeclaringType())
    )
  }
}

/** Holds if gadget entry `entry` (transitively) reaches action call `action`. */
predicate gadgetReachableAction(GadgetEntryPoint entry, GadgetActionCall action) {
  entry.calls*(action.getCaller())
}

/** Holds if gadget dispatch `link` (transitively) reaches action call `action`.
 *  These are the "dispatch" gadgets (e.g. `InvokerTransformer.transform`). */
predicate gadgetLinkReachesAction(GadgetLinkMethod link, GadgetActionCall action) {
  link.calls*(action.getCaller())
}

/**
 * Holds if `t` is one of the well-known ysoserial gadget source classes
 * (https://github.com/frohoff/ysoserial). Shared by the known-class query and
 * the novel-gadget query (which excludes these).
 */
predicate isKnownYsoserialGadgetClass(RefType t) {
  t.fromSource() and
  (
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
      "InvokerTransformer", "ChainedTransformer", "ConstantTransformer", "InstantiateTransformer"
    ])
    or
    t.hasQualifiedName("org.apache.commons.collections4.keyvalue", "TiedMapEntry")
    or
    t.hasQualifiedName("org.apache.commons.collections4.map", ["LazyMap", "DefaultedMap"])
    or
    t.hasQualifiedName("org.apache.commons.beanutils", ["BeanComparator", "PropertyUtilsBean"])
    or
    t.hasQualifiedName("com.sun.org.apache.xalan.internal.xsltc.trax", "TemplatesImpl")
    or
    t.hasQualifiedName("com.sun.org.apache.xalan.internal.xsltc.runtime", "AbstractTranslet")
    or
    t.hasQualifiedName("com.sun.org.apache.bcel.internal.util", "ClassLoader")
    or
    t.hasQualifiedName("javassist.util.proxy", ["ProxyFactory", "ProxyObject", "RuntimeSupport"])
    or
    t.hasQualifiedName("org.codehaus.groovy.runtime", [
      "ConvertedClosure", "MethodClosure", "ConversionHandler"
    ])
    or
    t.hasQualifiedName("org.springframework.beans.factory.config", "PropertyPathFactoryBean")
    or
    t.hasQualifiedName("org.springframework.transaction.jta", "JtaTransactionManager")
    or
    t.hasQualifiedName("org.springframework.aop.support", "AbstractBeanFactoryPointcutAdvisor")
    or
    t.hasQualifiedName("org.springframework.jndi", "JndiObjectFactoryBean")
    or
    t.hasQualifiedName("com.mchange.v2.c3p0", "WrapperConnectionPoolDataSource")
    or
    t.hasQualifiedName("org.hibernate.property", "BasicPropertyAccessor")
    or
    t.hasQualifiedName("org.apache.commons.fileupload.disk", "DiskFileItem")
    or
    t.hasQualifiedName("org.mozilla.javascript", ["NativeJavaObject", "FunctionObject", "MemberBox"])
    or
    t.hasQualifiedName("com.alibaba.fastjson", ["JSONArray", "JSONObject"])
    or
    t.hasQualifiedName("org.apache.myfaces.view.facelets.el", "ValueExpressionMethodExpression")
    or
    t.hasQualifiedName("org.apache.naming.resources", "ResourceRef")
    or
    t.hasQualifiedName("org.apache.commons.configuration", "ConfigurationMap")
    or
    t.hasQualifiedName("org.apache.wicket.util.link", "Link")
  )
}