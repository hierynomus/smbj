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
import com.hierynomus.smbj.common.SMBBuffer;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.valueOf;

/**
 * [MS-SMB2].pdf 2.2.32 SMB2 IOCTL Response
 * <p>
 * \
 */
public class SMB2IoctlResponse extends SMB2Packet {

    private SMB2IoctlRequest.ControlCode controlCode;
    private SMB2FileId fileId;

    byte[] inputBuffer;
    byte[] outputBuffer;

    public SMB2IoctlResponse() {
        super();
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        // TODO how to handle errors correctly
        if (header.getStatus() != NtStatus.STATUS_SUCCESS) return;

        buffer.skip(2); // StructureSize (2 bytes)
        buffer.skip(2); // Reserved (2 bytes)
        controlCode = valueOf(buffer.readUInt32(), SMB2IoctlRequest.ControlCode.class, null); // CtlCode (4 bytes)
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

    public byte[] getOutputBuffer() {
        return outputBuffer;
    }

    public void setOutputBuffer(byte[] outputBuffer) {
        this.outputBuffer = outputBuffer;
    }
    
    public byte[] getInputBuffer() {
        return inputBuffer;
    }
    
    public void setInputBuffer(byte[] inputBuffer) {
        this.inputBuffer = inputBuffer;
    }
}