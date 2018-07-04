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
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class FutureWrapper<T extends U, U> implements Future<T> {

    private final Future<U> mDelegate;

    public FutureWrapper(Future<U> delegate) {
        mDelegate = delegate;
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
        return mDelegate.cancel(mayInterruptIfRunning);
    }

    @Override
    public boolean isCancelled() {
        return mDelegate.isCancelled();
    }

    @Override
    public boolean isDone() {
        return mDelegate.isDone();
    }

    @Override
    public T get() throws InterruptedException, ExecutionException {
        //noinspection unchecked
        return (T)mDelegate.get();
    }

    @Override
    public T get(long timeout, TimeUnit unit)
        throws InterruptedException, ExecutionException, TimeoutException {
        //noinspection unchecked
        return (T)mDelegate.get(timeout, unit);
    }
}
