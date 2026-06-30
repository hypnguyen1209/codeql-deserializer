/**
 * @name Deserialization gadget action call
 * @description A call to an RCE/sensitive primitive (`Runtime.exec`,
 *              `ProcessBuilder.start`, `Method.invoke`, `Class.forName`,
 *              `ClassLoader.loadClass`, `ScriptEngine.eval`, JNDI `lookup`,
 *              `Templates.newTransformer`, `URL.openConnection`, ...). When
 *              such a call is reachable from a deserialization entry point it
 *              is the "action" of a ysoserial-style gadget chain (CWE-502).
 * @kind problem
 * @id java/deserialization/gadget-action
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
import gadgets.GadgetModel

from GadgetActionCall action
select action,
  "Gadget action call: " + action.getActionName() + "() can be the RCE action of a deserialization gadget chain."
