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

import com.hierynomus.mssmb2.*;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.io.ByteChunkProvider;

/**
 * [MS-SMB2].pdf 2.2.31 SMB2 IOCTL Request
 */
public class SMB2IoctlRequest extends SMB2MultiCreditPacket {

    private final long controlCode;
    private final SMB2FileId fileId;
    private final ByteChunkProvider inputData;
    private final boolean fsctl;
    private long maxOutputResponse;

    public SMB2IoctlRequest(
        SMB2Dialect negotiatedDialect, long sessionId, long treeId,
        long controlCode, SMB2FileId fileId,
        ByteChunkProvider inputData, boolean fsctl, int maxOutputResponse
    ) {
        super(57, negotiatedDialect, SMB2MessageCommandCode.SMB2_IOCTL, sessionId, treeId, Math.max(inputData.bytesLeft(), maxOutputResponse));
        this.controlCode = controlCode;
        this.fileId = fileId;
        this.inputData = inputData;
        this.fsctl = fsctl;
        this.maxOutputResponse = maxOutputResponse;
    }

    @Override
    protected void writeTo(SMBBuffer smbBuffer) {
        smbBuffer.putUInt16(structureSize); // StructureSize (2 bytes)
        smbBuffer.putReserved2(); // Reserved (2 bytes)
        smbBuffer.putUInt32(controlCode); // CtlCode (4 bytes)
        fileId.write(smbBuffer);  // FileId (16 bytes)

        int offset = SMB2Header.STRUCTURE_SIZE + 56;
        int inputDataSize = inputData.bytesLeft();
        if (inputDataSize > 0) {
            smbBuffer.putUInt32(offset); // InputOffset (4 bytes)
            smbBuffer.putUInt32(inputDataSize); // InputCount (4 bytes)
        } else {
            smbBuffer.putUInt32(0); // InputOffset (4 bytes)
            smbBuffer.putUInt32(0); // InputCount (4 bytes)
        }
        smbBuffer.putUInt32(0); // MaxInputResponse (4 bytes)
        smbBuffer.putUInt32(0); // OutputOffset (4 bytes)
        smbBuffer.putUInt32(0); // OutputCount (4 bytes)
        smbBuffer.putUInt32(maxOutputResponse); // MaxOutputResponse (4 bytes)
        smbBuffer.putUInt32(fsctl ? 1 : 0); // Flags (4 bytes)
        smbBuffer.putReserved4(); // Reserved (4 bytes)
        while (inputData.bytesLeft() > 0) {
            inputData.writeChunk(smbBuffer);
        }
    }
}
