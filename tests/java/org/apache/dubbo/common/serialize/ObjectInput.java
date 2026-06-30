package org.apache.dubbo.common.serialize;

public interface ObjectInput {
    Object readObject();
    Object readObject(Class<?> cls);
    int readInt();
}
