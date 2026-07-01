/**
 * @name Gadget chain steps (bounded call path)
 * @description Like `gadget-chain`, but renders the intermediate call path from
 *              the entry method to the method containing the RCE action, as
 *              `a -> b -> ... -> <action>`, over the static call graph (bounded
 *              to 4 hops). Use this to *see* short chains; use `gadget-chain` for
 *              the full list (it also catches chains reachable only via
 *              framework-dispatch edges, which this rendering may omit).
 * @kind problem
 * @id java/deserialization/gadget-chain-steps
 * @problem.severity error
 * @security-severity 9.0
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

/** Bounded (<=4 hops) non-recursive call path string from `entry` to action's caller. */
private predicate pathStr(GadgetEntryPoint entry, GadgetActionCall action, string s) {
  // 0 hop: action is directly inside the entry method
  entry = action.getCaller() and s = entry.getName()
  or
  exists(Method m1 | entry.calls(m1) and m1 = action.getCaller() |
    s = entry.getName() + " -> " + m1.getName())
  or
  exists(Method m1, Method m2 | entry.calls(m1) and m1.calls(m2) and m2 = action.getCaller() |
    s = entry.getName() + " -> " + m1.getName() + " -> " + m2.getName())
  or
  exists(Method m1, Method m2, Method m3 |
    entry.calls(m1) and m1.calls(m2) and m2.calls(m3) and m3 = action.getCaller() |
    s = entry.getName() + " -> " + m1.getName() + " -> " + m2.getName() + " -> " + m3.getName())
  or
  exists(Method m1, Method m2, Method m3, Method m4 |
    entry.calls(m1) and m1.calls(m2) and m2.calls(m3) and m3.calls(m4) and m4 = action.getCaller() |
    s = entry.getName() + " -> " + m1.getName() + " -> " + m2.getName() + " -> " + m3.getName() + " -> " + m4.getName())
}

from GadgetEntryPoint entry, GadgetActionCall action, string path
where
  gadgetReachableAction(entry, action) and
  pathStr(entry, action, path)
select entry,
  "Gadget chain [RCE:" + action.getActionName() + "]: " + entry.getDeclaringType().getName() + "." + path +
    " -> " + action.getActionName() + "()"
