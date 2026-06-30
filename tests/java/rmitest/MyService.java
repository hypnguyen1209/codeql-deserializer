package rmitest;

import java.rmi.Remote;
import java.rmi.RemoteException;

// Vulnerable: process() takes a complex object that Java deserializes over RMI.
public interface MyService extends Remote {
    Object process(MyData data) throws RemoteException;
}
