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

public class TransformedFuture<T, V> extends AFuture<V> {
    private AFuture<T> wrapped;
    private AFuture.Function<T, V> function;

    public TransformedFuture(AFuture<T> wrapped, Function<T, V> function) {
        this.wrapped = wrapped;
        this.function = function;
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
        return wrapped.cancel(mayInterruptIfRunning);
    }

    @Override
    public boolean isCancelled() {
        return wrapped.isCancelled();
    }

    @Override
    public boolean isDone() {
        return wrapped.isDone();
    }

    @Override
    public V get() throws InterruptedException, ExecutionException {
        return function.apply(wrapped.get());
    }

    @Override
    public V get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        return function.apply(wrapped.get(timeout, unit));
    }
}
