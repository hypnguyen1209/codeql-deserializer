package org.apache.dubbo.remoting;

import java.io.InputStream;
import org.apache.dubbo.common.serialize.ObjectInput;
import org.apache.dubbo.common.serialize.ObjectInputImpl;

public class DubboCodecImpl implements Codec2 {

    // Vulnerable: untrusted InputStream parameter flows into an ObjectInput
    // that is then deserialized (CVE-2020-11995 style).
    public Object decodeBody(Object channel, InputStream is, byte[] header) {
        ObjectInput input = new ObjectInputImpl(is);
        return input.readObject();
    }

    // Safe: the ObjectInput is built from a constant, not from the parameter.
    public Object decodeBodySafe(Object channel, InputStream is, byte[] header) {
        ObjectInput input = new ObjectInputImpl(null);
        return input.readObject();
    }
}
