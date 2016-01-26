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

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;

public class SMB2Packet extends SMBBuffer {
    protected final SMB2Header header = new SMB2Header();

    public SMB2Packet() {
        super();
    }

    public SMB2Packet(long messageId, SMB2MessageCommandCode messageType) {
        header.setMessageId(messageId);
        header.setMessageType(messageType);
    }

    public SMB2Header getHeader() {
        return header;
    }

    public long getSequenceNumber() {
        return header.getMessageId();
    }

    public final void write() {
        header.writeTo(this);
        writeMessage();
    }

    protected void writeMessage() {
        throw new UnsupportedOperationException("Should be implemented by specific message type");
    }

    public final SMB2Packet read(SMBBuffer buffer) throws BufferException {
        header.readFrom(buffer);
        readMessage(buffer);
        return this;
    }

    protected void readMessage(SMBBuffer buffer) throws BufferException {
        throw new UnsupportedOperationException("Should be implemented by specific message type");
    }
}
