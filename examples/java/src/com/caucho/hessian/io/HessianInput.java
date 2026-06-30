package com.caucho.hessian.io;
import java.io.InputStream;
public class HessianInput extends AbstractHessianInput {
    public HessianInput(InputStream is) { }
    public Object readObject() { return null; }
    public int readInt() { return 0; }
    public void readFully(byte[] b) { }
    public int available() { return 0; }
    public int read() { return 0; }
    public int read(byte[] b) { return 0; }
    public int read(byte[] b, int off, int len) { return 0; }
    public long skip(long n) { return 0; }
    public boolean readBoolean() { return false; }
    public byte readByte() { return 0; }
    public char readChar() { return 0; }
    public double readDouble() { return 0; }
    public float readFloat() { return 0; }
    public int readUnsignedByte() { return 0; }
    public int readUnsignedShort() { return 0; }
    public long readLong() { return 0; }
    public short readShort() { return 0; }
    public String readLine() { return null; }
    public String readUTF() { return null; }
    public int skipBytes(int n) { return 0; }
}
