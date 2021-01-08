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
package com.hierynomus.mssmb2.messages.negotiate;

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.common.SMBRuntimeException;

/**
 * [MS-SMB2].pdf 2.2.3.1 / 2.2.4.1 Negotiate Context Request/Response
 */
public abstract class SMB2NegotiateContext {

    private SMB2NegotiateContextType negotiateContextType;

    /**
     *  For request to create instance
     *
     * @param negotiateContextType the type of this negotiateContext
     */
    protected SMB2NegotiateContext(final SMB2NegotiateContextType negotiateContextType) {
        this.negotiateContextType = negotiateContextType;
        // make sure after write data is 8 byte alignment. Cast is safe, it will always be 0 ~ 7.
    }

    /**
     * Method to call for writing the Negotiate Context (one instance) to the buffer
     *
     * @param buffer the destination buffer to write to
     * @return The size in bytes of the SMB2NegotiateContext
     */
    public final int write(SMBBuffer buffer) {
        SMBBuffer tempBuffer = new SMBBuffer();
        int bytesWritten = writeContext(tempBuffer);
        writeContextHeader(buffer, bytesWritten);
        buffer.putBuffer(tempBuffer);
        return 8 + bytesWritten;
    }

    /**
     * Write the negotiate context fields into the buffer, as specified in the [MS-SMB2].pdf specification.
     */
    protected int writeContext(SMBBuffer buffer) {
        throw new UnsupportedOperationException("Should be implemented by specific SMB2NegotiateContext");
    }

    private void writeContextHeader(SMBBuffer buffer, int dataLength) {
        buffer.putUInt16((int) negotiateContextType.getValue()); // ContextType (2 bytes)
        buffer.putUInt16(dataLength); // DataLength (2 bytes)
        buffer.putReserved4(); // Reserved (4 bytes)
    }

    public static SMB2NegotiateContext factory(SMBBuffer buffer) throws Buffer.BufferException {
        int negotiateContextTypeId = buffer.readUInt16();
        SMB2NegotiateContextType negotiateContextType = EnumWithValue.EnumUtils.valueOf(negotiateContextTypeId, SMB2NegotiateContextType.class, null); // ContextType (2 bytes)
        switch (negotiateContextType) {
            case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
                return new SMB2PreauthIntegrityCapabilities().read(buffer);
            case SMB2_ENCRYPTION_CAPABILITIES:
                return new SMB2EncryptionCapabilities().read(buffer);
            case SMB2_COMPRESSION_CAPABILITIES:
                return new SMB2CompressionCapabilities().read(buffer);
            case SMB2_NETNAME_NEGOTIATE_CONTEXT_ID:
                return new SMB2NetNameNegotiateContextId().read(buffer);
        }
        throw new SMBRuntimeException("Unknown SMB2NegotiateContextType encountered: " + negotiateContextTypeId + " / " + negotiateContextType);
    }

    public final SMB2NegotiateContext read(SMBBuffer buffer) throws Buffer.BufferException {
        int dataSize = readContextHeader(buffer);
        readContext(buffer, dataSize);
        int dataAlignment = (dataSize % 8) == 0 ? 0 : (8 - (dataSize % 8));

        if (dataAlignment > 0 && buffer.available() >= dataAlignment) {
            // skip the alignment bytes, only when the context is not the last element
            buffer.skip(dataAlignment);
        }
        return this;
    }

    /**
     * Read the negotiate context
     *
     * @param buffer the buffer to read context
     * @throws Buffer.BufferException
     */
    protected void readContext(SMBBuffer buffer, int dataSize) throws Buffer.BufferException {
        throw new UnsupportedOperationException("Should be implemented by specific message type");
    }

    private int readContextHeader(SMBBuffer buffer) throws Buffer.BufferException {
        int size = buffer.readUInt16(); // DataLength (2 bytes)
        buffer.skip(4); // Reserved (4 bytes)
        return size;
    }

    public SMB2NegotiateContextType getNegotiateContextType() {
        return negotiateContextType;
    }
}
