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

import com.hierynomus.smbj.common.SMBRuntimeException;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class CancellableFuture<V> extends AFuture<V> {
    private final AFuture<V> wrappedFuture;
    private final CancelCallback callback;

    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public CancellableFuture(AFuture<V> wrappedFuture, CancelCallback cc) {
        this.wrappedFuture = wrappedFuture;
        this.callback = cc;
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
        lock.writeLock().lock();
        try {
            if (isDone() || cancelled.getAndSet(true)) {
                // Already done or cancelled
                return false;
            } else {
                callback.cancel();
                return true;
            }
        } catch (Throwable t) {
            cancelled.set(false);
            throw SMBRuntimeException.Wrapper.wrap(t);
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public boolean isCancelled() {
        lock.readLock().lock();
        try {
            return cancelled.get();
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public boolean isDone() {
        lock.readLock().lock();
        try {
            return cancelled.get() || wrappedFuture.isDone();
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public V get() throws InterruptedException, ExecutionException {
        return wrappedFuture.get();
    }

    @Override
    public V get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        return wrappedFuture.get(timeout, unit);
    }

    public interface CancelCallback {
        void cancel();
    }
}
