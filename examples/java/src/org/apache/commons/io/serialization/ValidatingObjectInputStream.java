package org.apache.commons.io.serialization;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
public class ValidatingObjectInputStream extends ObjectInputStream {
    public ValidatingObjectInputStream(InputStream is) throws IOException { super(is); }
}
