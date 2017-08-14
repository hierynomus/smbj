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
import com.hierynomus.smb.SMBHeader;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.isSet;

/**
 * [MS-SMB2].pdf 2.2.1 SMB2 Packet Header
 */
public class SMB2Header implements SMBHeader {
    public static final byte[] EMPTY_SIGNATURE = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    public static final int STRUCTURE_SIZE = 64;
    public static final int SIGNATURE_OFFSET = 48;
    public static final int SIGNATURE_SIZE = 16;

    private SMB2Dialect dialect;
    private int creditCharge = 1;
    private int creditRequest;
    private int creditResponse;
    private SMB2MessageCommandCode message;
    private long messageId;
    private long asyncId;
    private long sessionId;
    private long treeId;
    private NtStatus status;
    private long statusCode;
    private long flags;
    private long nextCommandOffset; // TODO Message Compounding
    private byte[] signature;

    @Override
    public void writeTo(SMBBuffer buffer) {
        buffer.putRawBytes(new byte[]{(byte) 0xFE, 'S', 'M', 'B'}); // ProtocolId (4 byte)
        buffer.putUInt16(STRUCTURE_SIZE); // StructureSize (2 byte)
        writeCreditCharge(buffer); // CreditCharge (2 byte)
        writeChannelSequenceReserved(buffer); // (ChannelSequence/Reserved)/Status (4 bytes)
        buffer.putUInt16(message.getValue()); // Command (2 bytes)
        writeCreditRequest(buffer); // CreditRequest (2 bytes)
        buffer.putUInt32(flags); // Flags (4 bytes)
        buffer.putUInt32(nextCommandOffset); // NextCommand (4 bytes)
        buffer.putUInt64(messageId); // MessageId (8 bytes)
        if (isSet(flags, SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND)) {
            buffer.putUInt64(asyncId);
        } else {
            buffer.putReserved4(); // Reserved (4 bytes)
            buffer.putUInt32(treeId); // TreeId (4 bytes)
        }
        buffer.putLong(sessionId); // SessionId (8 bytes)
        buffer.putRawBytes(EMPTY_SIGNATURE); // Signature (16 bytes)
    }

    private void writeChannelSequenceReserved(SMBBuffer buffer) {
        if (dialect.isSmb3x()) {
            buffer.putRawBytes(new byte[]{0x0, 0x0}); // ChannelSequence (2 bytes)
            buffer.putReserved(2); // Reserved (2 bytes)
            throw new UnsupportedOperationException("SMB 3.x not yet implemented");
        } else {
            buffer.putReserved4(); // Status (4 bytes) (reserved on request)
        }
    }

    /**
     * [MS-SMB2].pdf 3.2.4.1.2 Requesting Credits from the Server
     * <p>
     * We should at least request the number of credits this request consumes, but we can request more (by calling {@link #setCreditRequest(int)}).
     */
    private void writeCreditRequest(SMBBuffer buffer) {
        buffer.putUInt16(creditRequest + creditCharge); // Ask for the credit buffer wanted + what we use
    }

    private void writeCreditCharge(SMBBuffer buffer) {
        switch (dialect) {
            case UNKNOWN:
            case SMB_2_0_2:
                buffer.putReserved(2);
                break;
            default:
                buffer.putUInt16(creditCharge);
                break;
        }
    }

    public void setMessageId(long messageId) {
        this.messageId = messageId;
    }

    void setMessageType(SMB2MessageCommandCode messageType) {
        this.message = messageType;
    }

    public SMB2MessageCommandCode getMessage() {
        return message;
    }

    public long getTreeId() {
        return treeId;
    }

    public void setTreeId(long treeId) {
        this.treeId = treeId;
    }

    public long getSessionId() {
        return sessionId;
    }

    public void setSessionId(long sessionId) {
        this.sessionId = sessionId;
    }

    public void setDialect(SMB2Dialect dialect) {
        this.dialect = dialect;
    }

    public boolean isFlagSet(SMB2MessageFlag flag) {
        return isSet(this.flags, flag);
    }

    public void setFlag(SMB2MessageFlag flag) {
        this.flags |= flag.getValue();
    }

    public long getMessageId() {
        return messageId;
    }

    public void setCreditRequest(int creditRequest) {
        this.creditRequest = creditRequest;
    }

    public int getCreditResponse() {
        return creditResponse;
    }

    public void setAsyncId(long asyncId) {
        this.asyncId = asyncId;
    }

    public long getAsyncId() {
        return asyncId;
    }

    @Override
    public void readFrom(Buffer<?> buffer) throws Buffer.BufferException {
        buffer.skip(4); // ProtocolId (4 bytes) (already verified)
        buffer.skip(2); // StructureSize (2 bytes)
        buffer.readUInt16(); // CreditCharge (2 bytes)
        statusCode = buffer.readUInt32();
        status = EnumUtils.valueOf(statusCode, NtStatus.class, NtStatus.UNKNOWN); // Status (4 bytes)
        message = SMB2MessageCommandCode.lookup(buffer.readUInt16()); // Command (2 bytes)
        creditResponse = buffer.readUInt16(); // CreditRequest/CreditResponse (2 bytes)
        flags = buffer.readUInt32(); // Flags (4 bytes)
        nextCommandOffset = buffer.readUInt32(); // NextCommand (4 bytes)
        messageId = buffer.readUInt64(); // MessageId (4 bytes)
        if (isSet(flags, SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND)) {
            asyncId = buffer.readUInt64();
        } else {
            buffer.skip(4); // Reserved (4 bytes)
            treeId = buffer.readUInt32(); // TreeId (4 bytes)
        }
        sessionId = buffer.readLong(); // SessionId (8 bytes)
        signature = buffer.readRawBytes(16); // Signature (16 bytes)
    }

    public void setStatus(NtStatus status) {
        this.status = status;
    }

    public NtStatus getStatus() {
        return status;
    }

    public long getStatusCode() {
        return statusCode;
    }

    public long getFlags() {
        return flags;
    }

    public void setFlags(long flags) {
        this.flags = flags;
    }

    public long getNextCommandOffset() {
        return nextCommandOffset;
    }

    public void setNextCommandOffset(long nextCommandOffset) {
        this.nextCommandOffset = nextCommandOffset;
    }

    public void setCreditCharge(int creditCharge) {
        this.creditCharge = creditCharge;
    }

    public String toString() {
        return String.format(
            "dialect=%s, creditCharge=%s, creditRequest=%s, creditResponse=%s, message=%s, messageId=%s, asyncId=%s, sessionId=%s, treeId=%s, status=%s, statusCode=%s, flags=%s, nextCommandOffset=%s",
            dialect,
            creditCharge,
            creditRequest,
            creditResponse,
            message,
            messageId,
            asyncId,
            sessionId,
            treeId,
            status,
            statusCode,
            flags,
            nextCommandOffset);

    }

    public int getCreditCharge() {
        return creditCharge;
    }

    public byte[] getSignature() {
        return signature;
    }
}
