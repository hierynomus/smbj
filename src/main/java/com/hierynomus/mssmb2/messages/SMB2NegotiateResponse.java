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
package com.hierynomus.mssmb2.messages;

import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.util.UUID;

/**
 * [MS-SMB2].pdf 2.2.4 SMB2 Negotiate Response
 */
public class SMB2NegotiateResponse extends SMB2Packet {

    private int securityMode;
    private SMB2Dialect dialect;
    private UUID serverGuid;
    private long capabilities;
    private int maxTransactSize;
    private int maxReadSize;
    private int maxWriteSize;
    private FileTime systemTime;
    private FileTime serverStartTime;
    private byte[] gssToken;

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.skip(2); // StructureSize (2 bytes)
        securityMode = buffer.readUInt16(); // SecurityMode (2 bytes)
        dialect = SMB2Dialect.lookup(buffer.readUInt16()); // DialectRevision (2 bytes)
        int negotiateContextCount = readNegotiateContextCount(buffer); // NegotiateContextCount/Reserved (2 bytes)
        serverGuid = MsDataTypes.readGuid(buffer); // ServerGuid (16 bytes)
        capabilities = buffer.readUInt32(); // Capabilities (16 bytes)
        maxTransactSize = buffer.readUInt32AsInt(); // MaxTransactSize (4 bytes)
        maxReadSize = buffer.readUInt32AsInt(); // MaxReadSize (4 bytes)
        maxWriteSize = buffer.readUInt32AsInt(); // MaxWriteSize (4 bytes)
        systemTime = MsDataTypes.readFileTime(buffer); // SystemTime (8 bytes)
        serverStartTime = MsDataTypes.readFileTime(buffer); // ServerStartDate (8 bytes)
        int securityBufferOffset = buffer.readUInt16(); // SecurityBufferOffset (2 bytes)
        int securityBufferLength = buffer.readUInt16(); // SecurityBufferLength (2 bytes)
        int negotiateContextOffset = readNegotiateContextOffset(buffer); // NegotiateContextOffset/Reserved (2 bytes)
        gssToken = readSecurityBuffer(buffer, securityBufferOffset, securityBufferLength);
        readNegotiateContextList(buffer, negotiateContextOffset, negotiateContextCount);
    }

    private void readNegotiateContextList(SMBBuffer buffer, int negotiateContextOffset, @SuppressWarnings("unused") int negotiateContextCount) {
        if (dialect == SMB2Dialect.SMB_3_1_1) {
            buffer.rpos(negotiateContextOffset);
            throw new UnsupportedOperationException("Cannot read NegotiateContextList yet");
        }
    }

    private byte[] readSecurityBuffer(SMBBuffer buffer, int securityBufferOffset, int securityBufferLength) throws Buffer.BufferException {
        if (securityBufferLength > 0) {
            // Set the read pos to the start of the security buffer offset.
            buffer.rpos(securityBufferOffset);
            return buffer.readRawBytes(securityBufferLength);
        } else {
            return new byte[0];
        }
    }

    private int readNegotiateContextOffset(SMBBuffer buffer) throws Buffer.BufferException {
        if (dialect == SMB2Dialect.SMB_3_1_1) {
            return buffer.readUInt16();
        } else {
            buffer.skip(2);
            return 0;
        }
    }

    private int readNegotiateContextCount(Buffer<?> buffer) throws Buffer.BufferException {
        if (dialect == SMB2Dialect.SMB_3_1_1) {
            return buffer.readUInt16();
        } else {
            buffer.skip(2);
            return 0;
        }
    }

    public byte[] getGssToken() {
        return gssToken;
    }

    public int getSecurityMode() {
        return securityMode;
    }

    public SMB2Dialect getDialect() {
        return dialect;
    }

    public UUID getServerGuid() {
        return serverGuid;
    }

    public long getCapabilities() {
        return capabilities;
    }

    public int getMaxTransactSize() {
        return maxTransactSize;
    }

    public int getMaxReadSize() {
        return maxReadSize;
    }

    public int getMaxWriteSize() {
        return maxWriteSize;
    }

    public FileTime getSystemTime() {
        return systemTime;
    }

    public FileTime getServerStartTime() {
        return serverStartTime;
    }
}
