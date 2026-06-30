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
import gadgets.GadgetModel

from RefType t
where isKnownYsoserialGadgetClass(t)
select t,
  "Known ysoserial gadget class: " + t.getName() +
    " is part of the ysoserial payload catalog and can weaponise a deserialization sink."
