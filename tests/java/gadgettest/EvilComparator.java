package gadgettest;

import java.io.Serializable;
import java.util.Comparator;

// Gadget dispatch: Comparator.compare reaches Runtime.exec.
// Deserialization of a TreeMap/SortedSet keying on this comparator triggers compare().
public class EvilComparator implements Comparator<Object>, Serializable {
    private static final long serialVersionUID = 1L;
    private String cmd;

    public int compare(Object a, Object b) {
        try {
            Runtime.getRuntime().exec(cmd);     // gadget action
        } catch (Exception e) { }
        return 0;
    }
}
