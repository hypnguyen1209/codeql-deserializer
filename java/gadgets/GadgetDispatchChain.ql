/**
 * @name Deserialization dispatch gadget (link -> action)
 * @description A serializable "dispatch" method (`InvocationHandler.invoke`,
 *              `Comparator.compare`, `Map.get/put`, `equals/hashCode/toString`,
 *              ...) transitively reaches an RCE action call. ysoserial chains
 *              through exactly these methods (e.g.
 *              `InvokerTransformer.transform` -> `Method.invoke`,
 *              `AnnotationInvocationHandler.invoke` -> ...). Finding one means
 *              this class is a usable gadget dispatch for a deserialization
 *              exploit (CWE-502).
 * @kind problem
 * @id java/deserialization/gadget-dispatch
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @tag security
 * @tag external/cwe/cwe-502
 * @tags deserialization
 *      gadget
 *      ysoserial
 *      hunting
 */

import java
import gadgets.GadgetModel

from GadgetLinkMethod link, GadgetActionCall action
where gadgetLinkReachesAction(link, action)
select link,
  "Gadget dispatch: " + link.getDeclaringType().getName() + "." + link.getName() +
    "() reaches " + action.getActionName() + "() [" + action.getActionSeverity() + "] — " +
    "a deserialization gadget dispatch."
