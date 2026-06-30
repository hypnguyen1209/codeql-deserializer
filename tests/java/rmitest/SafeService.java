package rmitest;

import java.rmi.Remote;
import java.rmi.RemoteException;

// Safe: ping() only takes a String (no complex object deserialized over RMI).
public interface SafeService extends Remote {
    String ping(String s) throws RemoteException;
}
