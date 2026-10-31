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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.ExecutionException;

import org.junit.jupiter.api.Test;

import com.hierynomus.protocol.transport.TransportException;

public class PromiseBackedFutureTest {

    @Test
    public void shouldNotBeDoneBeforeDelivery() {
        Promise<String, TransportException> promise = new Promise<>("test", TransportException.Wrapper);
        assertFalse(promise.future().isDone());
    }

    @Test
    public void shouldBeDoneAfterValueDelivered() {
        Promise<String, TransportException> promise = new Promise<>("test", TransportException.Wrapper);
        promise.deliver("value");
        assertTrue(promise.future().isDone());
    }

    @Test
    public void shouldBeDoneAfterErrorDelivered() {
        Promise<String, TransportException> promise = new Promise<>("test", TransportException.Wrapper);
        AFuture<String> future = promise.future();
        promise.deliverError(new TransportException("failed"));
        assertTrue(future.isDone());
        assertThrows(ExecutionException.class, future::get);
    }
}
