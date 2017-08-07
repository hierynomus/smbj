package com.hierynomus.protocol.commons.concurrent;

import java.util.concurrent.Future;

public abstract class AFuture<V> implements Future<V> {
    public interface Function<A, B> {
        B apply(A a);
    }

    public <T> AFuture<T> map(Function<V, T> f) {
        return new TransformedFuture<>(this, f);
    }
}
