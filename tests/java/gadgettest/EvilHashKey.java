package gadgettest;

import java.io.Serializable;
import java.lang.reflect.Method;

// Inner gadget: a serializable map KEY whose hashCode() reaches a reflection
// action. A HashMap's readObject() calls key.hashCode() on every deserialized
// key -- the JDK dispatch the static call graph cannot see. Pairs with
// EvilMapHolder to exercise the framework-dispatch edge (pattern (b)).
public class EvilHashKey implements Serializable {
    private static final long serialVersionUID = 1L;
    private Method method;
    private Object target;

    public int hashCode() {
        try {
            method.invoke(target);          // gadget action (reflection), fired via HashMap dispatch
        } catch (Exception e) { }
        return 0;
    }
}
