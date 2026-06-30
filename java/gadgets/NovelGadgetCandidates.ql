/**
 * @name Novel deserialization gadget candidate
 * @description A deserialization entry point or dispatch method that
 *              transitively reaches an RCE action, but whose declaring type is
 *              NOT in the known ysoserial gadget catalog. These are candidate
 *              NEW gadgets to investigate — the daily hunting target (CWE-502).
 * @kind problem
 * @id java/deserialization/novel-gadget
 * @problem.severity error
 * @security-severity 8.5
 * @precision low
 * @tag security
 * @tag external/cwe/cwe-502
 * @tags deserialization
 *      gadget
 *      ysoserial
 *      hunting
 */

import java
import gadgets.GadgetModel

/** A gadget candidate method (entry or dispatch) that reaches an action. */
predicate gadgetCandidateReachesAction(Method m, GadgetActionCall action) {
  exists(GadgetEntryPoint e | e = m and gadgetReachableAction(e, action))
  or
  exists(GadgetLinkMethod l | l = m and gadgetLinkReachesAction(l, action))
}

from Method m, GadgetActionCall action
where
  gadgetCandidateReachesAction(m, action) and
  not isKnownYsoserialGadgetClass(m.getDeclaringType())
select m,
  "Novel gadget candidate: " + m.getDeclaringType().getName() + "." + m.getName() +
    "() reaches " + action.getActionName() + "() [" + action.getActionSeverity() + "] " +
    "and is not in the known ysoserial catalog — investigate as a new gadget."
