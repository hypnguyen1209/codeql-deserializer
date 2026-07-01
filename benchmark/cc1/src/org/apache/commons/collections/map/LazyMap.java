package org.apache.commons.collections.map;
import java.util.*;
import org.apache.commons.collections.functors.ChainedTransformer;
public class LazyMap extends AbstractMap<String, Object> {
    private final ChainedTransformer factory;
    public LazyMap(ChainedTransformer f) { this.factory = f; }
    public Object get(Object key) {
        try { return factory.transform(key); } catch (Exception e) { return null; }
    }
    public Set<Map.Entry<String, Object>> entrySet() { return Collections.emptySet(); }
}
