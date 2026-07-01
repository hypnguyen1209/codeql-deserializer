package gadgettest;

import java.io.ObjectInputStream;
import java.io.Serializable;
import java.io.IOException;

// Multi-hop gadget: readObject -> helper -> exec (tests GadgetChainSteps path rendering).
public class EvilMultiHop implements Serializable {
    private static final long serialVersionUID = 1L;
    private String cmd;

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        helper();                       // hop 1
    }

    private void helper() throws IOException {
        Runtime.getRuntime().exec(cmd); // action (hop 2)
    }
}
