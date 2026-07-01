package gadgettest;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.HashMap;

// Outer gadget: readObject() re-inserts an embedded EvilHashKey into a HashMap.
// On real deserialization HashMap.readObject() calls key.hashCode(), so the chain
// is  readObject -> (framework dispatch) -> EvilHashKey.hashCode -> Method.invoke.
// The static call graph never sees the hashCode() call; the dispatch edge (b) does,
// because this type embeds a field of the inner gadget's declared type.
public class EvilMapHolder implements Serializable {
    private static final long serialVersionUID = 1L;
    private EvilHashKey key;                 // embedded inner gadget (field-type match for dispatch (b))
    private HashMap<Object, Object> map;

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        map.put(key, "x");                   // container mutation; real HashMap.readObject -> key.hashCode()
    }
}
