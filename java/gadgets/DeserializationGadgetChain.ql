/**
 * @name Deserialization gadget chain (entry -> action)
 * @description A serializable type's `readObject`/`readResolve`/`readExternal`
 *              callback (the gadget entry point) transitively reaches an RCE
 *              action call (`Runtime.exec`, `Method.invoke`, JNDI `lookup`,
 *              ...). This is the entry-to-action reachability that makes a
 *              ysoserial-style gadget chain exploitable (CWE-502).
 * @kind problem
 * @id java/deserialization/gadget-chain
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @tag security
 * @tag external/cwe/cwe-502
 * @tags deserialization
 *      gadget
 *      ysoserial
 */

import java
import gadgets.GadgetModel

from GadgetEntryPoint entry, GadgetActionCall action
where gadgetReachableAction(entry, action)
select entry,
  "Gadget chain: " + entry.getDeclaringType().getName() + "." + entry.getName() +
    "() reaches " + action.getActionName() + "(), a deserialization RCE gadget."
