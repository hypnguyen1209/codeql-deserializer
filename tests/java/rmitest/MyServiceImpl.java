package rmitest;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class MyServiceImpl extends UnicastRemoteObject implements MyService {
    public MyServiceImpl() throws RemoteException {
        super();
    }
    public Object process(MyData data) {
        return data;
    }
}
