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
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 * [MS-SMB2].pdf 2.2.32 SMB2 IOCTL Response
 * <p>
 * \
 */
public class SMB2IoctlResponse extends SMB2Packet {

    private int controlCode;
    private SMB2FileId fileId;

    byte[] inputBuffer;
    byte[] outputBuffer;

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.skip(2); // StructureSize (2 bytes)
        buffer.skip(2); // Reserved (2 bytes)
        controlCode = buffer.readUInt32AsInt(); // CtlCode (4 bytes)
        fileId = SMB2FileId.read(buffer); // FileId (16 bytes)

        int inputOffset = buffer.readUInt32AsInt(); // Input Offset (4 bytes)
        int inputCount = buffer.readUInt32AsInt(); // Input Count (4 bytes)
        int outputOffset = buffer.readUInt32AsInt(); // Input Offset (4 bytes)
        int outputCount = buffer.readUInt32AsInt(); // Input Count (4 bytes)
        buffer.skip(4); // Flags (4 bytes)
        buffer.skip(4); // Reserved2 (4 bytes)

        if (inputCount > 0) {
            buffer.rpos(inputOffset);
            inputBuffer = buffer.readRawBytes(inputCount);
        }

        if (outputCount > 0) {
            buffer.rpos(outputOffset);
            outputBuffer = buffer.readRawBytes(outputCount);
        }

    }

    /**
     * [MS-SMB2].pdf 3.3.4.4
     * STATUS_BUFFER_OVERFLOW and STATUS_INVALID_PARAMETER should be treated as a success code.
     * @param status The status to verify
     * @return
     */
    @Override
    protected boolean isSuccess(NtStatus status) {
        return super.isSuccess(status) || status == NtStatus.STATUS_BUFFER_OVERFLOW || status == NtStatus.STATUS_INVALID_PARAMETER;
    }

    public byte[] getOutputBuffer() {
        return outputBuffer;
    }

    public byte[] getInputBuffer() {
        return inputBuffer;
    }

    public int getControlCode() {
        return controlCode;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }
}
