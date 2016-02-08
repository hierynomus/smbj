/*
 * Copyright (C)2016 - Jeroen van Erp <jeroen@hierynomus.com>
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
package com.hierynomus.smbj.smb2;

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.*;

/**
 * [MS-SMB2].pdf 2.2.1 SMB2 Packet Header
 */
public class SMB2Header {
    public static final int STRUCTURE_SIZE = 64;

    private SMB2Dialect dialect;
    private int creditCost;
    private int creditRequest;
    private int creditResponse;
    private SMB2MessageCommandCode message;
    private long messageId;
    private long sessionId;
    private long treeId;
    private byte[] status;
    private long flags;

    public SMB2Header() {
    }

    public void writeTo(SMBBuffer buffer) {
        buffer.putRawBytes(new byte[]{(byte) 0xFE, 'S', 'M', 'B'}); // ProtocolId (4 byte)
        buffer.putUInt16(STRUCTURE_SIZE); // StructureSize (2 byte)
        writeCreditCharge(buffer); // CreditCharge (2 byte)
        writeChannelSequenceReserved(buffer); // (ChannelSequence/Reserved)/Status (4 bytes)
        buffer.putUInt16(message.getValue()); // Command (2 bytes)
        buffer.putUInt16(creditRequest); // CreditRequest (2 bytes)
        buffer.putUInt32(flags); // Flags (4 bytes)
        buffer.putRawBytes(new byte[] {0x0, 0x0, 0x0, 0x0}); // NextCommand (4 bytes)
        buffer.putUInt64(messageId); // MessageId (8 bytes)
        if (isSet(flags, SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND)) {
            throw new UnsupportedOperationException("ASYNC not yet implemented");
        } else {
            buffer.putReserved4(); // Reserved (4 bytes)
            buffer.putUInt32(treeId); // TreeId (4 bytes)
        }
        buffer.putUInt64(sessionId); // SessionId (8 bytes)
        buffer.putRawBytes(new byte[] {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}); // Signature (16 bytes)
    }

    private void writeChannelSequenceReserved(SMBBuffer buffer) {
        if (dialect.isSmb3x()) {
            buffer.putRawBytes(new byte[] {0x0, 0x0}); // ChannelSequence (2 bytes)
            buffer.putReserved(2); // Reserved (2 bytes)
            throw new UnsupportedOperationException("SMB 3.x not yet implemented");
        } else {
            buffer.putReserved4(); // Status (4 bytes) (reserved on request)
        }
    }

    private void writeCreditCharge(SMBBuffer buffer) {
        switch (dialect) {
            case UNKNOWN:
            case SMB_2_0_2:
                buffer.putReserved(2);
                break;
            default:
                buffer.putUInt16(creditCost);
                break;
        }
    }

    public void setMessageId(long messageId) {
        this.messageId = messageId;
    }

    public void setMessageType(SMB2MessageCommandCode messageType) {
        this.message = messageType;
    }

    public SMB2MessageCommandCode getMessage() {
        return message;
    }

    public void setTreeId(long treeId) {
        this.treeId = treeId;
    }

    public void setSessionId(int sessionId) {
        this.sessionId = sessionId;
    }

    public void setDialect(SMB2Dialect dialect) {
        this.dialect = dialect;
    }

    public void setCreditCost(int creditCost) {
        this.creditCost = creditCost;
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

    public void readFrom(Buffer<?> buffer) throws Buffer.BufferException {
        buffer.skip(4); // ProtocolId (4 bytes) (already verified)
        buffer.skip(2); // StructureSize (2 bytes)
        creditCost = buffer.readUInt16(); // CreditCharge (2 bytes)
        status = buffer.readRawBytes(4); // Status (4 bytes)
        message = SMB2MessageCommandCode.lookup(buffer.readUInt16()); // Command (2 bytes)
        creditResponse = buffer.readUInt16(); // CreditRequest/CreditResponse (2 bytes)
        flags = buffer.readUInt32(); // Flags (4 bytes)
        buffer.readRawBytes(4); // NextCommand (4 bytes)
        messageId = buffer.readUInt64(); // MessageId (4 bytes)
        if (isSet(flags, SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND)) {
            throw new UnsupportedOperationException("ASYNC not implemented");
        } else {
            buffer.skip(4); // Reserved (4 bytes)
            treeId = buffer.readUInt32(); // TreeId (4 bytes)
        }
        sessionId = buffer.readUInt64(); // SessionId (8 bytes)
        buffer.readRawBytes(16); // Signature (16 bytes)
    }

    public void setStatus(byte[] status) {
        this.status = status;
    }
}
