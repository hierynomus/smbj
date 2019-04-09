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
package com.hierynomus.mssmb2.messages.submodule;

import com.hierynomus.mssmb2.SMB2NegotiateContextType;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

public abstract class SMB2NegotiateContext {

    private SMB2NegotiateContextType negotiateContextType;
    private int dataLength;
    private int dataAlignment;

    private SMBBuffer buffer;

    /***
     * For response to create instance
     */
    protected SMB2NegotiateContext() {
    }

    /***
     *  For request to create instance
     *
     * @param negotiateContextType the type of this negotiateContext
     * @param dataLength the length of the data (the buffer field) in this negotiateContext
     */
    protected SMB2NegotiateContext(final SMB2NegotiateContextType negotiateContextType, final int dataLength) {
        this.negotiateContextType = negotiateContextType;
        this.dataLength = dataLength;
        // make sure after write data is 8 byte alignment. Cast is safe, it will always be 0 ~ 7.
        this.dataAlignment = (dataLength % 8) == 0 ? 0 : (8 - (dataLength % 8));
    }

    /***
     * Method to call for writing the Negotiate Context (one instance) to the buffer
     *
     * @param buffer the destination buffer to write to
     */
    public void write(SMBBuffer buffer) {
        privateWriteTo(buffer);
        writeTo(buffer);
        if (this.dataAlignment > 0) {
            // put the alignment bytes
            buffer.putReserved(this.dataAlignment);
        }
    }

    /**
     * Write the negotiate context fields into the buffer, as specified in the [MS-SMB2].pdf specification.
     */
    protected void writeTo(SMBBuffer buffer) {
        throw new UnsupportedOperationException("Should be implemented by specific message type");
    }

    private void privateWriteTo(SMBBuffer buffer) {
        buffer.putUInt16((int) negotiateContextType.getValue()); // ContextType (2 bytes)
        buffer.putUInt16(dataLength); // DataLength (2 bytes)
        buffer.putReserved4(); // Reserved (4 bytes)
    }

    public final void read(SMBBuffer buffer) throws Buffer.BufferException {
        this.buffer = buffer; // remember the buffer we read it from
        privateReadFrom(buffer);
        readMessage(buffer);
        if (this.dataAlignment > 0 && buffer.available() >= this.dataAlignment) {
            // skip the alignment bytes, only when the context is not the last element
            buffer.skip(this.dataAlignment);
        }
    }

    /**
     * Read the negotiate context
     *
     * @param buffer the buffer to read context
     * @throws Buffer.BufferException
     */
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        throw new UnsupportedOperationException("Should be implemented by specific message type");
    }

    private void privateReadFrom(SMBBuffer buffer) throws Buffer.BufferException {
        this.negotiateContextType = EnumWithValue.EnumUtils.valueOf(buffer.readUInt16(), SMB2NegotiateContextType.class, null); // ContextType (2 bytes)
        this.dataLength = buffer.readUInt16(); // DataLength (2 bytes)
        // make sure after write data is 8 byte alignment. Cast is safe, it will always be 0 ~ 7.
        this.dataAlignment = (dataLength % 8) == 0 ? 0 : (8 - (dataLength % 8));
        buffer.skip(4); // Reserved (4 bytes)
    }

    protected int getDataAlignment() {
        return this.dataAlignment;
    }

    public SMB2NegotiateContextType getNegotiateContextType() {
        return negotiateContextType;
    }
}
