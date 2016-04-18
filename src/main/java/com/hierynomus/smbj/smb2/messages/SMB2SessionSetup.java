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
package com.hierynomus.smbj.smb2.messages;

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.smb2.SMB2Dialect;
import com.hierynomus.smbj.smb2.SMB2Header;
import com.hierynomus.smbj.smb2.SMB2MessageCommandCode;
import com.hierynomus.smbj.smb2.SMB2Packet;

import java.util.EnumSet;

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

    public SMB2SessionSetup() {
    }

    public SMB2SessionSetup(SMB2Dialect negotiatedDialect, EnumSet<SMB2SecurityMode> securityMode) {
        super(negotiatedDialect, SMB2MessageCommandCode.SMB2_SESSION_SETUP);
        this.negotiatedDialect = negotiatedDialect;
        this.securityMode = (byte)EnumWithValue.EnumUtils.toLong(securityMode);
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(25); // StructureSize (2 bytes)
        putFlags(buffer); // Flags (1 byte)
        buffer.putByte(securityMode); // SecurityMode (1 byte)
        buffer.putUInt32(clientCapabilities & 0x01); // Capabilities (4 bytes) (only last byte can be set)
        buffer.putReserved4(); // Channel (4 bytes)
        buffer.putUInt16(SMB2Header.STRUCTURE_SIZE + 25 - 1); // SecurityBufferOffset (2 bytes) (header structure size + Session setup structure size - 1)
        buffer.putUInt16(securityBuffer.length); // SecurityBufferLength (2 bytes)
        buffer.putUInt64(previousSessionId); // PreviousSessionId (8 bytes)
        buffer.putRawBytes(securityBuffer); // SecurityBuffer (variable)
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.readUInt16(); // StructureSize (2 bytes) (always 9)
        buffer.readUInt16(); // SessionFlags (2 bytes)
        int securityBufferOffset = buffer.readUInt16(); // SecurityBufferOffset (2 bytes)
        int securityBufferLength = buffer.readUInt16(); // SecurityBufferLength (2 bytes)
        securityBuffer = readSecurityBuffer(buffer, securityBufferOffset, securityBufferLength); // SecurityBuffer (variable)
    }

    private byte[] readSecurityBuffer(SMBBuffer buffer, int securityBufferOffset, int securityBufferLength) throws Buffer.BufferException {
        if (securityBufferLength > 0) {
            // Just to be sure, we should already be there.
            // TODO might need to subtract one, check!
            buffer.rpos(securityBufferOffset);
            return buffer.readRawBytes(securityBufferLength);
        }
        throw new SMBRuntimeException("The SMB2 Session Setup response should contain a positive length security buffer");
    }

    private void putFlags(SMBBuffer buffer) {
        if (negotiatedDialect.isSmb3x() && previousSessionId != 0L) {
            buffer.putByte((byte) 0x01);
        } else {
            buffer.putByte((byte) 0);
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

    public enum SMB2SecurityMode implements EnumWithValue<SMB2SecurityMode> {
        SMB2_NEGOTIATE_SIGNING_ENABLED(0x00000001),
        SMB2_NEGOTIATE_SIGNING_REQUIRED(0x00000002);

        private long value;

        SMB2SecurityMode(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }
    }

}
