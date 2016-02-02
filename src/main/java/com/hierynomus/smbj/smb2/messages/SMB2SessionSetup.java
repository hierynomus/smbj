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
package com.hierynomus.smbj.smb2.messages;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.common.SMBException;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.smb2.SMB2Dialect;
import com.hierynomus.smbj.smb2.SMB2Header;
import com.hierynomus.smbj.smb2.SMB2MessageCommandCode;
import com.hierynomus.smbj.smb2.SMB2Packet;

/**
 * [MS-SMB2].pdf 2.2.5 SMB2_SESSTION_SETUP Request / 2.2.6 SMB2_SESSION_SETUP Response
 */
public class SMB2SessionSetup extends SMB2Packet {

    private SMB2Dialect negotiatedDialect;
    private byte securityMode;
    private long clientCapabilities;
    private byte[] securityBuffer;
    private long previousSessionId;

    private int sessionFlags;

    public SMB2SessionSetup(SMB2Dialect negotiatedDialect) {
        this.negotiatedDialect = negotiatedDialect;
    }

    public SMB2SessionSetup(long messageId, SMB2MessageCommandCode messageType) {
        super(messageId, messageType);
    }

    @Override
    protected void writeMessage() {
        putUInt16(25); // StructureSize (2 bytes)
        putFlags(); // Flags (1 byte)
        putByte(securityMode); // SecurityMode (1 byte)
        putUInt32(clientCapabilities & 0x00000001); // Capabilities (4 bytes) (only last byte can be set)
        putReserved4(); // Channel (4 bytes)
        putUInt16(SMB2Header.STRUCTURE_SIZE + 25); // SecurityBufferOffset (2 bytes) (header structure size + Session setup structure size)
        putUInt16(securityBuffer.length); // SecurityBufferLength (2 bytes)
        putUInt64(previousSessionId); // PreviousSessionId (8 bytes)
        putRawBytes(securityBuffer); // SecurityBuffer (variable)
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws BufferException {
        buffer.readUInt16(); // StructureSize (2 bytes) (always 9)
        buffer.readUInt16(); // SessionFlags (2 bytes)
        int securityBufferOffset = buffer.readUInt16(); // SecurityBufferOffset (2 bytes)
        int securityBufferLength = buffer.readUInt16(); // SecurityBufferLength (2 bytes)
        securityBuffer = readSecurityBuffer(buffer, securityBufferOffset, securityBufferLength); // SecurityBuffer (variable)
    }

    private byte[] readSecurityBuffer(SMBBuffer buffer, int securityBufferOffset, int securityBufferLength) throws BufferException {
        if (securityBufferLength > 0) {
            // Just to be sure, we should already be there.
            buffer.rpos(securityBufferOffset);
            return buffer.readRawBytes(securityBufferLength);
        }
        throw new SMBRuntimeException("The SMB2 Session Setup response should contain a positive length security buffer");
    }

    private void putFlags() {
        if (negotiatedDialect.isSmb3x() && previousSessionId != 0L) {
            putByte((byte) 0x01);
        } else {
            putByte((byte) 0);
        }
    }

    public void setPreviousSessionId(long previousSessionId) {
        this.previousSessionId = previousSessionId;
    }

    public void setSecurityBuffer(byte[] securityBuffer) {
        this.securityBuffer = securityBuffer;
    }

    public byte[] getSecurityBuffer() {
        return securityBuffer;
    }
}
