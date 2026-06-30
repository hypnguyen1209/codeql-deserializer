package gadgettest;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

// Vulnerable: readObject() (gadget entry) reaches Runtime.exec (action).
public class EvilGadget implements Serializable {
    private static final long serialVersionUID = 1L;
    private String cmd;

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        Runtime.getRuntime().exec(cmd);          // gadget action
    }
}
