package org.apache.dubbo.remoting;

import java.io.InputStream;

public interface Codec2 {
    Object decodeBody(Object channel, InputStream is, byte[] header);
}
