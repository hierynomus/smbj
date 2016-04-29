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
package com.hierynomus.smbj.smb2;

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;

public class SMB2Packet implements Packet<SMB2Packet, SMBBuffer> {
    protected final SMB2Header header = new SMB2Header();
    protected int structureSize;

    public SMB2Packet() {
    }

    public SMB2Packet(int structureSize, SMB2Dialect dialect, SMB2MessageCommandCode messageType) {
        this.structureSize = structureSize;
        header.setDialect(dialect);
        header.setMessageType(messageType);
    }

    public SMB2Packet(int structureSize, SMB2Dialect dialect, SMB2MessageCommandCode messageType, long sessionId, long treeId) {
        this.structureSize = structureSize;
        header.setDialect(dialect);
        header.setMessageType(messageType);
        header.setSessionId(sessionId);
        header.setTreeId(treeId);
    }

    public SMB2Header getHeader() {
        return header;
    }

    public long getSequenceNumber() {
        return header.getMessageId();
    }

    public int getStructureSize() {
        return structureSize;
    }

    public final void write(SMBBuffer buffer) {
        header.writeTo(buffer);
        writeTo(buffer);
    }

    /**
     * Write the message fields into the buffer, as specified in the [MS-SMB2].pdf specification.
     * @param buffer
     */
    protected void writeTo(SMBBuffer buffer) {
        throw new UnsupportedOperationException("Should be implemented by specific message type");
    }

    public final SMB2Packet read(SMBBuffer buffer) throws Buffer.BufferException {
        header.readFrom(buffer);
        readMessage(buffer);
        return this;
    }

    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        throw new UnsupportedOperationException("Should be implemented by specific message type");
    }
}
