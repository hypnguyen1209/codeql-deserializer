package org.apache.commons.collections.functors;
import java.lang.reflect.*;
public class InvokerTransformer {
    public Object transform(Object input) throws Exception {
        Method m = Runtime.class.getMethod("exec", String.class);
        return m.invoke(Runtime.getRuntime(), input.toString());
    }
}
