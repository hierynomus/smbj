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
package com.hierynomus.smbj.connection;

import com.hierynomus.protocol.commons.concurrent.Promise;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.smb2.SMB2Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock;

class Request {

    private final Promise<SMB2Packet, SMBRuntimeException> promise;
    private final long messageId;
    private final UUID cancelId;
    private SMB2Packet requestPacket;
    private final Date timestamp;
    private long asyncId;

    public long getAsyncId() {
        return asyncId;
    }

    public void setAsyncId(long asyncId) {
        this.asyncId = asyncId;
    }

    public Request(long messageId, UUID cancelId, SMB2Packet requestPacket) {
        this.messageId = messageId;
        this.cancelId = cancelId;
        this.requestPacket = requestPacket;
        timestamp = new Date();
        this.promise = new Promise<>(String.valueOf(messageId), SMBRuntimeException.Wrapper);
    }

    Promise<SMB2Packet, SMBRuntimeException> getPromise() {
        return promise;
    }

    SMB2Packet getRequestPacket() {
        return requestPacket;
    }

    long getMessageId() {
        return messageId;
    }

    <T extends SMB2Packet> Future<T> getFuture(final CancelCallback callback) {
        return new Future<T>() {
            private final Logger logger = LoggerFactory.getLogger(Request.class);
            private final AtomicBoolean cancelled = new AtomicBoolean(false);
            private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

            @Override
            public boolean cancel(boolean mayInterruptIfRunning) {
                lock.writeLock().lock();
                try {
                    if (isDone() || cancelled.getAndSet(true)) {
                        // Already done or cancelled
                        return false;
                    } else {
                        callback.cancel(messageId);
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
                    return cancelled.get() || promise.isDelivered();
                } finally {
                    lock.readLock().unlock();
                }
            }

            @Override
            public T get() throws InterruptedException, ExecutionException {
                logger.debug("Retrieving value for Future << {} >>", messageId);
                //noinspection unchecked
                return (T) promise.retrieve();
            }

            @Override
            public T get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
                //noinspection unchecked
                return (T) promise.retrieve(timeout, unit);
            }
        };
    }

    UUID getCancelId() {
        return cancelId;
    }

    interface CancelCallback {
        void cancel(long messageId);
    }
}
