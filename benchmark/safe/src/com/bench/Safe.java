package com.bench;
import java.io.*;
public class Safe implements Serializable {
    private static final long serialVersionUID = 1L;
    private int x;
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        this.x = this.x + 1;   // benign
    }
}
