package rmitest;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

public class Server {
    public static void main(String[] args) throws Exception {
        // Vulnerable: a remote object with a complex-typed method is exported
        // and bound to the registry (RMI parameter deserialization -> RCE).
        MyService obj = new MyServiceImpl();
        MyService stub = (MyService) UnicastRemoteObject.exportObject(obj, 0);
        Registry registry = LocateRegistry.getRegistry();
        registry.bind("MyService", stub);

        // Safe: the bound remote object only accepts primitives/strings.
        SafeService sobj = new SafeServiceImpl();
        SafeService sstub = (SafeService) UnicastRemoteObject.exportObject(sobj, 0);
        registry.rebind("SafeService", sstub);
    }
}
