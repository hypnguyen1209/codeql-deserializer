package springexporter;

import org.springframework.remoting.rmi.RemoteInvocationSerializingExporter;

// A Spring remoting exporter that deserializes request bodies with ObjectInputStream.
public class MyExporter extends RemoteInvocationSerializingExporter {
}
