package gadgettest;

import java.io.Serializable;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

// Gadget link: InvocationHandler.invoke reaches Method.invoke (reflection action).
public class EvilHandler implements InvocationHandler, Serializable {
    private static final long serialVersionUID = 1L;
    private Method method;
    private Object target;

    public Object invoke(Object proxy, Method m, Object[] args) throws Throwable {
        return method.invoke(target, args);      // gadget action (reflection)
    }
}
