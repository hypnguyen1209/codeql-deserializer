package org.nibblesec.tools;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
public class SerialKiller extends ObjectInputStream {
    public SerialKiller(InputStream is) throws IOException { super(is); }
}
