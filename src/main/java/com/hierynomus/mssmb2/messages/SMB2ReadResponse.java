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

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 * [MS-SMB2].pdf 2.2.20 SMB2 READ Response
 */
public class SMB2ReadResponse extends SMB2Packet {

    private int dataLength;
    private byte[] data;

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.skip(2); // StructureSize (2 bytes)
        byte dataOffset = buffer.readByte(); // DataOffset (1 byte)
        buffer.skip(1); // Reserved (1 byte)
        dataLength = buffer.readUInt32AsInt(); // DataLength (4 bytes)
        buffer.readUInt32AsInt(); // DataRemaining (4 bytes)
        buffer.skip(4); // Reserved2 (4 bytes)
        buffer.rpos(dataOffset);
        data = buffer.readRawBytes(dataLength); // Buffer (variable)
    }

    /**
     * [MS-SMB2].pdf 3.3.4.4
     * STATUS_BUFFER_OVERFLOW should be treated as a success code.
     * @param status The status to verify
     * @return
     */
    @Override
    protected boolean isSuccess(NtStatus status) {
        return super.isSuccess(status) || status == NtStatus.STATUS_BUFFER_OVERFLOW;
    }

    public int getDataLength() {
        return dataLength;
    }

    public byte[] getData() {
        return data;
    }
}
