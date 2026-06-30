/**
 * @name Deserialization gadget entry point
 * @description A `Serializable` type declares a `readObject`/`readResolve`/
 *              `readExternal`/`readObjectNoData` callback. ysoserial-style
 *              gadget chains start here: `ObjectInputStream.readObject()` calls
 *              these on attacker-controlled data, so any non-trivial work they
 *              do is a gadget candidate (CWE-502).
 * @kind problem
 * @id java/deserialization/gadget-entry
 * @problem.severity warning
 * @security-severity 6.0
 * @precision high
 * @tag security
 * @tag external/cwe/cwe-502
 * @tags deserialization
 *      gadget
 *      ysoserial
 */

import java
import gadgets.GadgetModel

from GadgetEntryPoint entry
select entry,
  "Deserialization gadget entry point: " + entry.getName() + "() on serializable " +
    entry.getDeclaringType().getName() + " is invoked on attacker-controlled data."
