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
import com.hierynomus.mssmb2.SMB2PacketHeader;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.protocol.commons.concurrent.AFuture;
import com.hierynomus.protocol.commons.concurrent.CancellableFuture;
import com.hierynomus.protocol.commons.concurrent.Promise;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.common.SMBRuntimeException;

import java.util.Date;
import java.util.UUID;

public class Request {

    private final Promise<SMB2Packet, SMBRuntimeException> promise;
    private SMBPacket<?, ?> packet;
    private final long messageId;
    private final UUID cancelId;
    private final SMB2MessageCommandCode command;
    private final long sessionId;
    private final boolean encrypted;
    private final boolean signingRequired;
    private final Date timestamp;
    private volatile long asyncId;

    public Request(SMBPacket<?, ?> packet, long messageId, UUID cancelId) {
        this(packet, messageId, cancelId, false);
    }

    Request(SMBPacket<?, ?> packet, long messageId, UUID cancelId, boolean signingRequired) {
        this.packet = packet instanceof SMB2Packet ? ((SMB2Packet) packet).getPacket() : packet;
        this.encrypted = packet instanceof PacketEncryptor.EncryptedPacketWrapper;
        this.signingRequired = signingRequired;
        this.messageId = messageId;
        this.cancelId = cancelId;
        if (packet.getHeader() instanceof SMB2PacketHeader) {
            SMB2PacketHeader header = (SMB2PacketHeader) packet.getHeader();
            this.command = header.getMessage();
            this.sessionId = header.getSessionId();
        } else {
            // An SMB1 multi-protocol negotiate request receives an SMB2 NEGOTIATE response.
            this.command = SMB2MessageCommandCode.SMB2_NEGOTIATE;
            this.sessionId = 0;
        }
        timestamp = new Date();
        this.promise = new Promise<>(String.valueOf(messageId), SMBRuntimeException.Wrapper);
    }

    public long getAsyncId() {
        return asyncId;
    }

    /**
     * Returns the command captured when this request was registered for sending.
     * @return the request command
     */
    public SMB2MessageCommandCode getCommand() {
        return command;
    }

    /**
     * Returns the session ID captured when this request was registered for sending.
     * @return the request session ID
     */
    public long getSessionId() {
        return sessionId;
    }

    /**
     * Returns whether this request was registered for sending inside an SMB2 TRANSFORM frame.
     * @return true if the request was sent encrypted
     */
    public boolean isEncrypted() {
        return encrypted;
    }

    /**
     * Returns whether the request's session required signing when it was registered for sending.
     * @return true if the session required signing
     */
    public boolean isSigningRequired() {
        return signingRequired;
    }

    public void setAsyncId(long asyncId) {
        this.asyncId = asyncId;
    }

    public Promise<SMB2Packet, SMBRuntimeException> getPromise() {
        return promise;
    }

    long getMessageId() {
        return messageId;
    }

    @SuppressWarnings("unchecked")
    <T extends SMB2Packet> AFuture<T> getFuture(final CancellableFuture.CancelCallback callback) {
        return (AFuture<T>) new CancellableFuture<>(promise.future(), callback);

    }

    UUID getCancelId() {
        return cancelId;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public SMBPacket<?, ?> getPacket() {
        return packet;
    }
}
