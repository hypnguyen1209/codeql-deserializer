package com.caucho.hessian.io;
public abstract class AbstractHessianInput implements java.io.ObjectInput {
    public abstract Object readObject();
    public abstract int readInt();
    public abstract void readFully(byte[] b);
    public abstract int available();
    public abstract int read();
    public abstract int read(byte[] b);
    public abstract int read(byte[] b, int off, int len);
    public abstract long skip(long n);
    public abstract boolean readBoolean();
    public abstract byte readByte();
    public abstract char readChar();
    public abstract double readDouble();
    public abstract float readFloat();
    public abstract int readUnsignedByte();
    public abstract int readUnsignedShort();
    public abstract long readLong();
    public abstract short readShort();
    public abstract String readLine();
    public abstract String readUTF();
    public abstract int skipBytes(int n);
}
