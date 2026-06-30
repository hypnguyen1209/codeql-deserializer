package org.apache.dubbo.common.serialize;

import java.io.InputStream;

public class ObjectInputImpl implements ObjectInput {
    private final InputStream in;

    public ObjectInputImpl(InputStream in) {
        this.in = in;
    }

    public Object readObject() {
        return new Object();
    }

    public Object readObject(Class<?> cls) {
        return new Object();
    }

    public int readInt() {
        return 0;
    }
}
