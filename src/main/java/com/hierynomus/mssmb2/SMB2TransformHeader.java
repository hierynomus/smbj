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
    public static final byte[] ENCRYPTED_PROTOCOL_ID = {(byte) 0xFD, 'S', 'M', 'B'};
    private int headerStartPosition;
    private byte[] signature;
    private byte[] nonce;
    private int originalMessageSize;
    private int flagsEncryptionAlgorithm;
    private long sessionId;
    private int messageEndPosition;

    public SMB2TransformHeader(byte[] signature, byte[] nonce, int originalMessageSize, long sessionId) {
        this.signature = signature;
        this.nonce = nonce;
        this.originalMessageSize = originalMessageSize;
        this.sessionId = sessionId;
    }

    public SMB2TransformHeader() {
    }

    @Override
    public void writeTo(SMBBuffer buffer) {
        this.headerStartPosition = buffer.rpos(); // Keep track of the header start position.
        buffer.putRawBytes(ENCRYPTED_PROTOCOL_ID); // ProtocolId (4 bytes)
        buffer.putRawBytes(signature); // Signature (16 bytes)
        buffer.putRawBytes(nonce); // Nonce (16 bytes)
        buffer.putUInt32(originalMessageSize); // OriginalMessageSize (4 bytes)
        buffer.putReserved2(); // Reserved (2 bytes)
        buffer.putUInt16(0x01); // Flags/EncryptionAlgorithm (2 bytes)
        buffer.putLong(sessionId); // SessionId (8 bytes)
    }

    @Override
    public void readFrom(Buffer<?> buffer) throws Buffer.BufferException {
        this.headerStartPosition = buffer.rpos(); // Keep track of the header start position.
        byte[] protocolId = buffer.readRawBytes(4); // ProtocolId (4 bytes) (already verified)
        Check.ensureEquals(protocolId, ENCRYPTED_PROTOCOL_ID, "Could not find SMB2 Packet header");
        this.signature = buffer.readRawBytes(16); // Signature (16 bytes)
        this.nonce = buffer.readRawBytes(16); // Nonce (16 bytes)
        this.originalMessageSize = buffer.readUInt32AsInt(); // OriginalMessageSize (4 bytes)
        buffer.skip(2); // Reserved (2 bytes)
        this.flagsEncryptionAlgorithm = buffer.readUInt16(); // Flags/EncryptionAlgorithm (2 bytes)
        this.sessionId = buffer.readLong(); // SessionId (8 bytes)
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

    public void setMessageEndPosition(int messageEndPosition) {
        this.messageEndPosition = messageEndPosition;
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
