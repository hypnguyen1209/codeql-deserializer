package rmitest;

import java.rmi.RemoteException;

// Note: deliberately does NOT extend UnicastRemoteObject, so it does not pull in
// java.rmi.server.RemoteObject's complex-typed methods (e.g. equals(Object)).
// Its only remote method ping(String) is safe because String is excluded.
public class SafeServiceImpl implements SafeService {
    public SafeServiceImpl() {
    }
    public String ping(String s) {
        return s;
    }
}
