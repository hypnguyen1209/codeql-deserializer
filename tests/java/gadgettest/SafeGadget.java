package gadgettest;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

// Safe: readObject() does no sensitive action (no reachable RCE primitive).
public class SafeGadget implements Serializable {
    private static final long serialVersionUID = 1L;
    private int x;

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        this.x = this.x + 1;                     // no gadget action
    }
}
