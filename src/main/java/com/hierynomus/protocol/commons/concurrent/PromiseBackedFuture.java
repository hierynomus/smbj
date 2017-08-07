package com.hierynomus.protocol.commons.concurrent;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class PromiseBackedFuture<V> extends AFuture<V> {
    private Promise<V, ?> promise;

    public PromiseBackedFuture(Promise<V, ?> promise) {
        this.promise = promise;
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
        // TODO
        return false;
    }

    @Override
    public boolean isCancelled() {
        // TODO
        return false;
    }

    @Override
    public boolean isDone() {
        return promise.isDelivered();
    }

    @Override
    public V get() throws InterruptedException, ExecutionException {
        try {
            return promise.retrieve();
        } catch (Throwable t) {
            throw new ExecutionException(t);
        }
    }

    @Override
    public V get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        try {
            return promise.retrieve(timeout, unit);
        } catch (Throwable t) {
            throw new ExecutionException(t);
        }
    }
}
