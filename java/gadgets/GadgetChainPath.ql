/**
 * @name Deserialization gadget chain (path)
 * @description A serializable type's `readObject`/`readResolve`/`readExternal`
 *              callback (the gadget entry point) transitively reaches an RCE
 *              action call (`Runtime.exec`, `Method.invoke`, JNDI `lookup`, ...).
 *              Unlike `gadget-chain` (which reports only the two endpoints), this
 *              is a **path-problem**: it builds its own graph over the static call
 *              graph plus framework-dispatch edges and renders the full
 *              intermediate path (`readObject -> ... -> hashCode -> invoke ->
 *              exec`) in the SARIF code-flow / VS Code results view. Bounded to a
 *              configurable call depth so it stays tractable on large databases
 *              (CWE-502).
 * @kind path-problem
 * @id java/deserialization/gadget-chain-path
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
import GadgetChainPathGraph

/**
 * Custom path graph over the call graph. Nodes are `Method`s on a gadget chain
 * plus the terminal `GadgetActionCall` expression; edges follow static calls and
 * framework-dispatch edges (see `dispatchEdge` in `GadgetModel`). Everything is
 * bounded by `maxChainDepth()` so the two transitive closures below cannot blow
 * up on a huge database.
 */
module GadgetChainPathGraph {
  /** Maximum number of call hops explored from entry and toward an action. */
  private int maxChainDepth() { result = 8 }

  /** A call-graph edge: a resolved static call, or a framework-dispatch edge. */
  private predicate callEdge(Method a, Method b) {
    a.calls(b)
    or
    dispatchEdge(a, b)
  }

  /** Holds if `m` is within `d` (<= `maxChainDepth`) hops *forward* from a gadget entry. */
  private predicate fromEntry(Method m, int d) {
    m instanceof GadgetEntryPoint and d = 0
    or
    exists(Method p, int dp |
      fromEntry(p, dp) and dp < maxChainDepth() and callEdge(p, m) and d = dp + 1
    )
  }

  /** Holds if `m` reaches an action within `d` (<= `maxChainDepth`) hops. */
  private predicate reachesAction(Method m, int d) {
    exists(GadgetActionCall a | a.getCaller() = m) and d = 0
    or
    exists(Method n, int dn |
      reachesAction(n, dn) and dn < maxChainDepth() and callEdge(m, n) and d = dn + 1
    )
  }

  /** Holds if `m` genuinely lies on some entry -> action chain (pruned node set). */
  predicate onChain(Method m) { fromEntry(m, _) and reachesAction(m, _) }

  /** Path-graph edges. `Element` is the common supertype of `Method` and the
   *  terminal action `Expr`, so both kinds of node carry a source location. */
  query predicate edges(Element a, Element b) {
    // method -> callee, both pruned to the chain
    a instanceof Method and
    b instanceof Method and
    onChain(a) and
    onChain(b) and
    callEdge(a, b)
    or
    // method -> the RCE action call it contains (terminal step)
    onChain(a) and
    b.(GadgetActionCall).getCaller() = a
  }
}

from GadgetEntryPoint entry, GadgetActionCall action
where
  GadgetChainPathGraph::onChain(entry) and
  edges+(entry, action)
select action, entry, action,
  "Gadget chain: " + entry.getDeclaringType().getName() + "." + entry.getName() +
    "() reaches RCE " + action.getActionName() + "() [" + action.getActionSeverity() + "]."
