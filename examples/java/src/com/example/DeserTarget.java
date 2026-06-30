package com.example;

import java.io.*;
import java.beans.XMLDecoder;
import java.net.Socket;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;

import com.caucho.hessian.io.HessianInput;

import org.apache.commons.io.serialization.ValidatingObjectInputStream;
import org.nibblesec.tools.SerialKiller;

public class DeserTarget {

    // ---- Vulnerable: ObjectInputStream.readObject ----
    public Object oisObject(Socket sock) throws Exception {
        InputStream is = sock.getInputStream();
        return new ObjectInputStream(is).readObject();
    }

    // ---- Vulnerable: ObjectInputStream.readUnshared ----
    public Object oisUnshared(Socket sock) throws Exception {
        InputStream is = sock.getInputStream();
        return new ObjectInputStream(is).readUnshared();
    }

    // ---- Vulnerable: XMLDecoder.readObject ----
    public Object xmlDecoder(Socket sock) {
        InputStream is = sock.getInputStream();
        return new XMLDecoder(is).readObject();
    }

    // ---- Safe: ValidatingObjectInputStream (whitelist) ----
    public Object validatingOis(Socket sock) throws Exception {
        InputStream is = sock.getInputStream();
        return new ValidatingObjectInputStream(is).readObject();
    }

    // ---- Safe: SerialKiller (whitelist) ----
    public Object serialKiller(Socket sock) throws Exception {
        InputStream is = sock.getInputStream();
        return new SerialKiller(is).readObject();
    }

    // ---- Vulnerable: XStream.fromXML ----
    public Object xstream(Socket sock) {
        InputStream is = sock.getInputStream();
        XStream xs = new XStream();
        return xs.fromXML(is);
    }

    // ---- Safe: XStream whitelist via addPermission(NoTypePermission.NONE) ----
    public Object xstreamSafe(Socket sock) {
        InputStream is = sock.getInputStream();
        XStream xs = new XStream();
        xs.addPermission(NoTypePermission.NONE);
        return xs.fromXML(is);
    }

    // ---- Vulnerable: Kryo.readClassAndObject ----
    public Object kryo(Socket sock) {
        InputStream is = sock.getInputStream();
        Kryo kryo = new Kryo();
        return kryo.readClassAndObject(new Input(is));
    }

    // ---- Safe: Kryo setRegistrationRequired(true) ----
    public Object kryoSafe(Socket sock) {
        InputStream is = sock.getInputStream();
        Kryo kryo = new Kryo();
        kryo.setRegistrationRequired(true);
        return kryo.readClassAndObject(new Input(is));
    }

    // ---- Vulnerable: SnakeYAML Yaml.load ----
    public Object snakeyaml(Socket sock) {
        InputStream is = sock.getInputStream();
        return new Yaml().load(is);
    }

    // ---- Safe: SnakeYAML new Yaml(new SafeConstructor()) ----
    public Object snakeyamlSafe(Socket sock) {
        InputStream is = sock.getInputStream();
        return new Yaml(new SafeConstructor()).load(is);
    }

    // ---- Vulnerable: Jackson polymorphic (enableDefaultTyping) ----
    public Object jackson(Socket sock) throws Exception {
        InputStream is = sock.getInputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        return mapper.readValue(is, Object.class);
    }

    // ---- Safe: Jackson setPolymorphicTypeValidator ----
    public Object jacksonSafe(Socket sock) throws Exception {
        InputStream is = sock.getInputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.setPolymorphicTypeValidator(new PolymorphicTypeValidator());
        return mapper.readValue(is, Object.class);
    }

    // ---- Vulnerable: Hessian HessianInput.readObject ----
    public Object hessian(Socket sock) throws IOException {
        InputStream is = sock.getInputStream();
        return new HessianInput(is).readObject();
    }
}
