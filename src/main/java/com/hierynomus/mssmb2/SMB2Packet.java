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
package com.hierynomus.mssmb2;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBPacket;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.isSet;

public class SMB2Packet extends SMBPacket<SMB2Header> {
    public static final int SINGLE_CREDIT_PAYLOAD_SIZE = 64 * 1024;
    protected int structureSize;
    private SMBBuffer buffer;
    private SMB2Error error;
    private int messageStartPos;
    private int messageEndPos;

    protected SMB2Packet() {
        super(new SMB2Header());
    }

    protected SMB2Packet(int structureSize, SMB2Dialect dialect, SMB2MessageCommandCode messageType) {
        this(structureSize, dialect, messageType, 0, 0);
    }

    protected SMB2Packet(int structureSize, SMB2Dialect dialect, SMB2MessageCommandCode messageType, long sessionId) {
        this(structureSize, dialect, messageType, sessionId, 0);
    }

    protected SMB2Packet(int structureSize, SMB2Dialect dialect, SMB2MessageCommandCode messageType, long sessionId, long treeId) {
        super(new SMB2Header());
        this.structureSize = structureSize;
        header.setDialect(dialect);
        header.setMessageType(messageType);
        header.setSessionId(sessionId);
        header.setTreeId(treeId);
    }

    public long getSequenceNumber() {
        return header.getMessageId();
    }

    public int getStructureSize() {
        return structureSize;
    }

    /**
     * The buffer from which this packet is read if it was a received packet
     * @return The buffer
     */
    public SMBBuffer getBuffer() {
        return buffer;
    }

    /**
     * The start position of this packet in the {@link #getBuffer()}. Normally this is 0, except
     * when this packet was compounded.
     * @return The start position of this received packet in the buffer
     */
    public int getMessageStartPos() {
        return messageStartPos;
    }

    /**
     * THe end position of this packet in the {@link #getBuffer()}. Normally this is the last written position,
     * except when this packet was compounded.
     * @return The end position of this received packet in the buffer
     */
    public int getMessageEndPos() {
        return messageEndPos;
    }

    public void write(SMBBuffer buffer) {
        header.writeTo(buffer);
        writeTo(buffer);
    }

    /**
     * Write the message fields into the buffer, as specified in the [MS-SMB2].pdf specification.
     *
     * @param buffer
     */
    protected void writeTo(SMBBuffer buffer) {
        throw new UnsupportedOperationException("Should be implemented by specific message type");
    }

    public final void read(SMBBuffer buffer) throws Buffer.BufferException {
        this.buffer = buffer; // remember the buffer we read it from
        this.messageStartPos = buffer.rpos();
        header.readFrom(buffer);
        if (isSuccess(header.getStatus())) {
            readMessage(buffer);
        } else {
            readError(buffer);
        }
        this.messageEndPos = buffer.rpos();
    }

    protected void readError(SMBBuffer buffer) throws Buffer.BufferException {
        this.error = new SMB2Error().read(header, buffer);
    }

    /**
     * Read the message, this is only called in case the response is a success response according to {@link #isSuccess(NtStatus)}
     *
     * @param buffer
     * @throws Buffer.BufferException
     */
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        throw new UnsupportedOperationException("Should be implemented by specific message type");
    }

    /**
     * Callback to verify whether the status is a success status. Some responses have error codes that should be treated as success responses.
     * @param status The status to verify
     * @return {@code true} is {@link NtStatus#isSuccess()}
     */
    protected boolean isSuccess(NtStatus status) {
        return status.isSuccess() && status != NtStatus.STATUS_PENDING;
    }

    /**
     * Check whether this packet is an intermediate ASYNC response
     */
    public boolean isIntermediateAsyncResponse() {
        return isSet(header.getFlags(), SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND) && header.getStatus() == NtStatus.STATUS_PENDING;
    }

    /**
     * Returns the maximum payload size of this packet. Normally this is the {@link #SINGLE_CREDIT_PAYLOAD_SIZE}.
     * Can be overridden in subclasses to support multi-credit messages.
     *
     * @return
     */
    public int getMaxPayloadSize() {
        return SINGLE_CREDIT_PAYLOAD_SIZE;
    }

    public int getCreditsAssigned() {
        return getHeader().getCreditCharge();
    }
    public void setCreditsAssigned(int creditsAssigned) {
        getHeader().setCreditCharge(creditsAssigned);
    }

    public SMB2Error getError() {
        return error;
    }

    @Override
    public String toString() {
        return header.getMessage() + " with message id << " + header.getMessageId() + " >>";
    }
}
