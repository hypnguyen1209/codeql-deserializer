package com.fasterxml.jackson.databind;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
public class ObjectMapper {
    public void enableDefaultTyping() { }
    public void setPolymorphicTypeValidator(PolymorphicTypeValidator v) { }
    public Object readValue(java.io.InputStream is, Class<?> t) { return null; }
    public Object readValue(String s, Class<?> t) { return null; }
    public Object readValues(java.io.InputStream is, Class<?> t) { return null; }
    public Object treeToValue(Object n, Class<?> t) { return null; }
}
