package com.fasterxml.jackson.annotation;
import java.lang.annotation.*;
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface JsonTypeInfo {
    String use() default "NONE";
}
