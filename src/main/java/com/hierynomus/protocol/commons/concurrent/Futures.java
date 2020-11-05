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

import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.hierynomus.protocol.commons.concurrent.AFuture.Function;

public class Futures {

    public static <T, E extends Throwable> T get(Future<T> future, ExceptionWrapper<E> wrapper) throws E {
        try {
            return future.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw wrapper.wrap(e);
        } catch (ExecutionException e) {
            throw wrapper.wrap(e);
        }
    }

    public static <T, E extends Throwable> T get(Future<T> future, long timeout, TimeUnit unit,
            ExceptionWrapper<E> wrapper) throws E {
        try {
            return future.get(timeout, unit);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw wrapper.wrap(e);
        } catch (ExecutionException | TimeoutException e) {
            throw wrapper.wrap(e);
        }
    }

    public static <T> Future<List<T>> sequence(List<Future<T>> futures) {
        return new SequencedFuture<T>(futures);
    }

    public static <F, T> Future<T> transform(Future<F> future, Function<F, T> f) {
        return new TransformedFuture<F, T>(future, f);
    }
}
