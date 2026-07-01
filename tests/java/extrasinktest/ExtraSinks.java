package extrasinktest;

import com.caucho.hessian.io.Hessian2Input;
import com.esotericsoftware.kryo.Kryo;

// Exercises the #5 extra deserialization sinks with in-source stubs so they
// resolve under buildless extraction. The model also matches the JDK
// java.rmi.MarshalledObject.get() and javax.management.remote.rmi.RMIConnection
// sinks, but those only resolve in a real/decompiled build (as the benchmark uses),
// not in this buildless unit test.
public class ExtraSinks {
    Object viaHessian(Hessian2Input in) {
        return in.readObject();                 // Hessian2Input sink
    }

    Object viaKryo(Kryo k, Object input) {
        return k.readClassAndObject(input);     // Kryo sink
    }
}
