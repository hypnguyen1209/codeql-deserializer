/**
 * ysoserial-style deserialization gadget model (CWE-502).
 *
 * Concepts + call-graph reachability + ysoserial known-gadget catalog, plus
 * framework-dispatch edges (HashMap/TreeMap/proxy calling hashCode/equals/
 * compare on deserialized values). All entry/link/catalog predicates are
 * restricted to target source (`.fromSource()`).
 */

import java

/** Holds if `t` is (transitively) `java.io.Serializable`. */
predicate isSerializableType(RefType t) {
  t.getASupertype*().hasQualifiedName("java.io", "Serializable")
}

/**
 * A call to an RCE/sensitive primitive (the "action" end of a ysoserial chain):
 * Runtime.exec, ProcessBuilder.start, reflection (Method/Constructor/Class),
 * ClassLoader.loadClass, scripting (ScriptEngine/JShell/Groovy/MVEL),
 * JNDI (InitialContext.lookup/bind/rebind, JMX MBeanServer.invoke), XSLT
 * (Templates/TransformerFactory), expression languages (OGNL/SpEL),
 * templating (Velocity/Freemarker), URL.openConnection, URLClassLoader.
 */
class GadgetActionCall extends MethodCall {
  GadgetActionCall() {
    exists(Method m | m = this.getMethod() |
      m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and m.hasName("exec")
      or
      m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and m.hasName("start")
      or
      m.getDeclaringType().getASupertype*().hasQualifiedName("java.lang.reflect", "Method") and m.hasName("invoke")
      or
      m.getDeclaringType().getASupertype*().hasQualifiedName("java.lang", "Class") and m.hasName(["forName", "newInstance"])
      or
      m.getDeclaringType().getASupertype*().hasQualifiedName("java.lang.reflect", "Constructor") and m.hasName("newInstance")
      or
      m.getDeclaringType().getASupertype*().hasQualifiedName("java.lang", "ClassLoader") and m.hasName("loadClass")
      or
      m.getDeclaringType().getASupertype*().hasQualifiedName("javax.script", "ScriptEngine") and m.hasName("eval")
      or
      m.getDeclaringType().getASupertype*().hasQualifiedName("javax.naming", "InitialContext") and m.hasName(["lookup", "bind", "rebind"])
      or
      m.hasName("newTransformer") and m.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.transform", "Templates")
      or
      m.getDeclaringType().hasQualifiedName("javax.xml.transform", "TransformerFactory") and m.hasName("newTransformer")
      or
      m.getDeclaringType().hasQualifiedName("java.net", "URL") and m.hasName("openConnection")
      or
      m.getDeclaringType().hasQualifiedName("java.net", "URLClassLoader") and m.hasName(["newInstance", "loadClass"])
      or
      // JMX
      m.getDeclaringType().getASupertype*().hasQualifiedName("javax.management", "MBeanServer") and m.hasName("invoke")
      or
      // Groovy
      (
        m.getDeclaringType().getASupertype*().hasQualifiedName("groovy.lang", "GroovyShell") or
        m.getDeclaringType().getASupertype*().hasQualifiedName("groovy.lang", "GroovyClassLoader")
      ) and m.hasName(["evaluate", "parseClass"])
      or
      // JShell
      m.getDeclaringType().getASupertype*().hasQualifiedName("jdk.jshell", "JShell") and m.hasName("eval")
      or
      // OGNL
      m.getDeclaringType().getASupertype*().hasQualifiedName("ognl", ["OgnlUtil", "Ognl"]) and m.hasName(["getValue", "parseExpression"])
      or
      // MVEL
      m.getDeclaringType().getASupertype*().hasQualifiedName("org.mvel2", "MVEL") and m.hasName(["eval", "executeExpression"])
      or
      // Spring SpEL
      m.getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.expression", ["ExpressionParser", "Expression"]) and
        m.hasName(["parseExpression", "getValue"])
      or
      // Velocity / Freemarker
      m.getDeclaringType().getASupertype*().hasQualifiedName("org.apache.velocity.app", "Velocity") and m.hasName("evaluate")
      or
      m.getDeclaringType().getASupertype*().hasQualifiedName("freemarker.template", "Template") and m.hasName("process")
    )
  }

  string getActionName() { result = this.getMethod().getName() }

  string getActionSeverity() {
    if this.getActionName() = ["exec", "start", "lookup", "eval", "loadClass", "getValue", "executeExpression", "process"]
    then result = "critical"
    else (
      if this.getActionName() = ["invoke", "newInstance", "forName", "newTransformer", "openConnection", "parseClass", "parseExpression"]
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
    method.hasName("readObject") and method.getNumberOfParameters() = 1 and
    method.getParameter(0).getType().(RefType).getASupertype*().hasQualifiedName("java.io", "ObjectInputStream")
    or
    method.hasName("readObjectNoData") and method.getNumberOfParameters() = 0
    or
    method.hasName("readResolve") and method.getNumberOfParameters() = 0
    or
    method.hasName("readExternal") and method.getNumberOfParameters() = 1 and
    method.getParameter(0).getType().(RefType).getASupertype*().hasQualifiedName("java.io", "ObjectInput")
  )
}

/** A deserialization gadget *entry point* (Serializable readObject/readResolve/readExternal/readObjectNoData). */
class GadgetEntryPoint extends Method {
  GadgetEntryPoint() { isDeserializationCallback(this) }
}

/** A *gadget link* method: InvocationHandler.invoke, Comparator.compare/Comparable.compareTo,
 *  Map.get/put/entrySet/containsKey, and Object.equals/hashCode/toString on serializable types. */
class GadgetLinkMethod extends Method {
  GadgetLinkMethod() {
    this.fromSource() and
    (
      this.hasName("invoke") and this.getDeclaringType().getASupertype*().getSourceDeclaration().hasQualifiedName("java.lang.reflect", "InvocationHandler")
      or
      this.hasName(["compare", "compareTo"]) and
      (
        this.getDeclaringType().getASupertype*().getSourceDeclaration().hasQualifiedName("java.util", "Comparator") or
        this.getDeclaringType().getASupertype*().getSourceDeclaration().hasQualifiedName("java.lang", "Comparable")
      )
      or
      this.hasName(["get", "put", "entrySet", "containsKey"]) and this.getDeclaringType().getASupertype*().getSourceDeclaration().hasQualifiedName("java.util", "Map")
      or
      this.hasName(["equals", "hashCode", "toString"]) and isSerializableType(this.getDeclaringType())
    )
  }
}

/**
 * Framework-dispatch edge (#4): `from` calls a method whose name matches a known
 * gadget-link dispatch verb (hashCode/equals/compare/get/put/entrySet/invoke) on
 * some receiver, and `to` is a serializable gadget link with that name. This models
 * HashMap/TreeMap readObject -> key.hashCode()/compare(), proxy -> InvocationHandler.invoke,
 * etc., where static call resolution can't bind the receiver. Over-approximate by design.
 */
predicate dispatchEdge(Method src, GadgetLinkMethod dst) {
  exists(MethodCall mc |
    mc.getCaller() = src and
    mc.getMethod().hasName(dst.getName())
  )
}

/**
 * Maximum number of call-graph hops explored by the reachability predicates
 * below. A depth cap keeps the transitive closure from blowing up on very large
 * databases (real ysoserial-style chains are well under this many hops). Raise it
 * only if you knowingly hunt very deep chains.
 */
int gadgetMaxCallDepth() { result = 10 }

/** Holds if `dst` is reachable from `src` in exactly `d` (0..cap) `calls` hops. */
private predicate callsAtDepth(Callable src, Callable dst, int d) {
  src = dst and d = 0
  or
  d in [1 .. gadgetMaxCallDepth()] and
  exists(Callable mid | callsAtDepth(src, mid, d - 1) and mid.calls(dst))
}

/** Reflexive-transitive `calls`, bounded to `gadgetMaxCallDepth()` hops (the
 *  depth-capped replacement for `calls*`). */
predicate callsWithinDepth(Callable src, Callable dst) { callsAtDepth(src, dst, _) }

/** Holds if gadget entry `entry` reaches action `action` (bounded calls + dispatch edges). */
predicate gadgetReachableAction(GadgetEntryPoint entry, GadgetActionCall action) {
  callsWithinDepth(entry, action.getCaller())
  or
  exists(GadgetLinkMethod link | dispatchEdge+(entry, link) and callsWithinDepth(link, action.getCaller()))
}

/** Holds if gadget dispatch `link` reaches action `action` (bounded calls + dispatch edges). */
predicate gadgetLinkReachesAction(GadgetLinkMethod link, GadgetActionCall action) {
  callsWithinDepth(link, action.getCaller())
  or
  exists(GadgetLinkMethod l2 | dispatchEdge+(link, l2) and callsWithinDepth(l2, action.getCaller()))
}

/** Holds if `t` is one of the well-known ysoserial gadget source classes. */
predicate isKnownYsoserialGadgetClass(RefType t) {
  t.fromSource() and
  (
    t.hasQualifiedName("org.apache.commons.collections.functors", ["InvokerTransformer", "ChainedTransformer", "ConstantTransformer", "InstantiateTransformer", "TransformedMap"])
    or t.hasQualifiedName("org.apache.commons.collections.keyvalue", "TiedMapEntry")
    or t.hasQualifiedName("org.apache.commons.collections.map", ["LazyMap", "DefaultedMap"])
    or t.hasQualifiedName("org.apache.commons.collections4.functors", ["InvokerTransformer", "ChainedTransformer", "ConstantTransformer", "InstantiateTransformer"])
    or t.hasQualifiedName("org.apache.commons.collections4.keyvalue", "TiedMapEntry")
    or t.hasQualifiedName("org.apache.commons.collections4.map", ["LazyMap", "DefaultedMap"])
    or t.hasQualifiedName("org.apache.commons.beanutils", ["BeanComparator", "PropertyUtilsBean"])
    or t.hasQualifiedName("com.sun.org.apache.xalan.internal.xsltc.trax", "TemplatesImpl")
    or t.hasQualifiedName("com.sun.org.apache.xalan.internal.xsltc.runtime", "AbstractTranslet")
    or t.hasQualifiedName("com.sun.org.apache.bcel.internal.util", "ClassLoader")
    or t.hasQualifiedName("javassist.util.proxy", ["ProxyFactory", "ProxyObject", "RuntimeSupport"])
    or t.hasQualifiedName("org.codehaus.groovy.runtime", ["ConvertedClosure", "MethodClosure", "ConversionHandler"])
    or t.hasQualifiedName("org.springframework.beans.factory.config", "PropertyPathFactoryBean")
    or t.hasQualifiedName("org.springframework.transaction.jta", "JtaTransactionManager")
    or t.hasQualifiedName("org.springframework.aop.support", "AbstractBeanFactoryPointcutAdvisor")
    or t.hasQualifiedName("org.springframework.jndi", "JndiObjectFactoryBean")
    or t.hasQualifiedName("com.mchange.v2.c3p0", "WrapperConnectionPoolDataSource")
    or t.hasQualifiedName("org.hibernate.property", "BasicPropertyAccessor")
    or t.hasQualifiedName("org.apache.commons.fileupload.disk", "DiskFileItem")
    or t.hasQualifiedName("org.mozilla.javascript", ["NativeJavaObject", "FunctionObject", "MemberBox"])
    or t.hasQualifiedName("com.alibaba.fastjson", ["JSONArray", "JSONObject"])
    or t.hasQualifiedName("org.apache.myfaces.view.facelets.el", "ValueExpressionMethodExpression")
    or t.hasQualifiedName("org.apache.naming.resources", "ResourceRef")
    or t.hasQualifiedName("org.apache.commons.configuration", "ConfigurationMap")
    or t.hasQualifiedName("org.apache.wicket.util.link", "Link")
    or t.hasQualifiedName("org.codehaus.groovy.runtime", "ConvertedClosure")
  )
}