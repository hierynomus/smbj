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

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBHeader;
import com.hierynomus.smbj.common.Check;

/**
 * [MS-SMB2] 2.2.41 SMB2 TRANSFORM_HEADER
 * <p>
 * The SMB2 TRANSFORM_HEADER is used by the client or server when sending encrypted messages.
 * The SMB2 TRANSFORM_HEADER is only valid for the SMB 3.x dialect family.
 */
public class SMB2TransformHeader implements SMBHeader {
    private int headerStartPosition;
    private byte[] signature;
    private byte[] nonce;
    private int originalMessageSize;
    private int flagsEncryptionAlgorithm;
    private long sessionId;
    private int messageEndPosition;

    @Override
    public void writeTo(SMBBuffer buffer) {

    }

    @Override
    public void readFrom(Buffer<?> buffer) throws Buffer.BufferException {
        this.headerStartPosition = buffer.rpos(); // Keep track of the header start position.
        byte[] protocolId = buffer.readRawBytes(4); // ProtocolId (4 bytes) (already verified)
        Check.ensureEquals(protocolId, new byte[]{(byte) 0xFD, 'S', 'M', 'B'}, "Could not find SMB2 Packet header");
        this.signature = buffer.readRawBytes(16); // Signature (16 bytes)
        this.nonce = buffer.readRawBytes(16); // Nonce (16 bytes)
        this.originalMessageSize = buffer.readUInt32AsInt(); // OriginalMessageSize (4 bytes)
        buffer.skip(2); // Reserved (2 bytes)
        this.flagsEncryptionAlgorithm = buffer.readUInt16(); // Flags/EncryptionAlgorithm (2 bytes)
        this.sessionId = buffer.readUInt64(); // SessionId (8 bytes)
        this.messageEndPosition = buffer.wpos();
    }

    @Override
    public int getHeaderStartPosition() {
        return headerStartPosition;
    }

    @Override
    public int getMessageEndPosition() {
        return messageEndPosition;
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public int getOriginalMessageSize() {
        return originalMessageSize;
    }

    public int getFlagsEncryptionAlgorithm() {
        return flagsEncryptionAlgorithm;
    }

    public long getSessionId() {
        return sessionId;
    }
}
