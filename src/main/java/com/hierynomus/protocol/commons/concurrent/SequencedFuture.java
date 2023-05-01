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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * SequencedFuture transforms a {@code List<Future<V>>} into a {@code Future<List<V>>}.
 */
public class SequencedFuture<V> extends AFuture<List<V>> {
    private List<Future<V>> futures;

    public SequencedFuture(List<Future<V>> futures) {
        this.futures = futures;
    }

    @Override
    public boolean isCancelled() {
        for (Future<V> future : futures) {
            if (!future.isCancelled()) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
        boolean allCancelled = true;
        for (Future<V> future : futures) {
            allCancelled = allCancelled && future.cancel(mayInterruptIfRunning);
        }
        return allCancelled;
    }

    @Override
    public boolean isDone() {
        for (Future<V> future : futures) {
            if (!future.isDone()) {
                return false;
            }
        }
        return true;
    }

    @Override
    public List<V> get() throws InterruptedException, ExecutionException {
        List<V> collector = new ArrayList<V>();
        for (Future<V> future : futures) {
            collector.add(future.get());
        }
        return collector;
    }

    @Override
    public List<V> get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        List<V> collector = new ArrayList<V>();
        for (Future<V> future : futures) {
            collector.add(future.get(timeout, unit));
        }
        return collector;
    }
}
