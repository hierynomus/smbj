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
 * [MS-SMB2].pdf 2.2.21 SMB2 Write Request
 */
public class SMB2WriteRequest extends SMB2MultiCreditPacket {

    private final SMB2FileId fileId;
    private final ByteChunkProvider byteProvider;

    public SMB2WriteRequest(
        SMB2Dialect negotiatedDialect, SMB2FileId fileId, long sessionId, long treeId,
        ByteChunkProvider byteProvider, int maxPayloadSize) {
        super(49, negotiatedDialect, SMB2MessageCommandCode.SMB2_WRITE, sessionId, treeId, Math.min(maxPayloadSize, byteProvider.bytesLeft()));
        this.fileId = fileId;
        this.byteProvider = byteProvider;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(structureSize); // StructureSize (2 bytes)
        short dataOffset = SMB2Header.STRUCTURE_SIZE + 48;
        buffer.putUInt16(dataOffset); // DataOffSet (2 bytes)
        buffer.putUInt32(getPayloadSize()); // Length (4 bytes)
        buffer.putUInt64(byteProvider.getOffset()); // Offset (8 bytes)
        fileId.write(buffer);  // FileId (16 bytes)
        buffer.putUInt32(0); // Channel (4 bytes)
        buffer.putUInt32(Math.max(0, byteProvider.bytesLeft() - getPayloadSize())); // RemainingBytes (4 bytes)
        buffer.putUInt16(0); // WriteChannelInfoOffset (2 bytes)
        buffer.putUInt16(0); // WriteChannelInfoLength (2 bytes)
        buffer.putUInt32(0); // Flags (4 bytes)
        byteProvider.writeChunks(buffer, getCreditsAssigned());
    }
}
