/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
