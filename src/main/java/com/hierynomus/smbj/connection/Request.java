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

import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.concurrent.AFuture;
import com.hierynomus.protocol.commons.concurrent.CancellableFuture;
import com.hierynomus.protocol.commons.concurrent.Promise;
import com.hierynomus.smbj.common.SMBRuntimeException;

import java.util.Date;
import java.util.UUID;

class Request {

    private final Promise<SMB2Packet, SMBRuntimeException> promise;
    private final long messageId;
    private final UUID cancelId;
    private final Date timestamp;
    private long asyncId;

    public long getAsyncId() {
        return asyncId;
    }

    public void setAsyncId(long asyncId) {
        this.asyncId = asyncId;
    }

    public Request(long messageId, UUID cancelId) {
        this.messageId = messageId;
        this.cancelId = cancelId;
        timestamp = new Date();
        this.promise = new Promise<>(String.valueOf(messageId), SMBRuntimeException.Wrapper);
    }

    Promise<SMB2Packet, SMBRuntimeException> getPromise() {
        return promise;
    }

    long getMessageId() {
        return messageId;
    }

    <T extends SMB2Packet> AFuture<T> getFuture(final CancellableFuture.CancelCallback callback) {
        //noinspection unchecked
        return (AFuture<T>) new CancellableFuture<>(promise.future(), callback);

    }

    UUID getCancelId() {
        return cancelId;
    }

    public Date getTimestamp() {
        return timestamp;
    }

}
