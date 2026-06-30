package desertest;

import java.io.*;
import java.net.Socket;

public class A {
  // Vulnerable: remote-controlled InputStream -> ObjectInputStream.readObject()
  public Object deserialize(Socket sock) throws IOException, ClassNotFoundException {
    InputStream inputStream = sock.getInputStream();
    ObjectInputStream in = new ObjectInputStream(inputStream);
    return in.readObject();
  }

  // Safe: hardcoded constant bytes, no remote source.
  public Object deserializeConstant() throws IOException, ClassNotFoundException {
    byte[] data = new byte[] { 1, 2, 3 };
    ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(data));
    return in.readObject();
  }
}
