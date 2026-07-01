package com.bench;
import java.io.*;
import java.util.*;
import org.apache.commons.beanutils.BeanComparator;
// BeanUtils chain: TreeMap(BeanComparator) readObject -> compare -> Templates.newTransformer (action)
public class Gadget implements Serializable {
    private static final long serialVersionUID = 1L;
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        // deserializing a TreeMap keyed by BeanComparator triggers compare() -> newTransformer
    }
}
