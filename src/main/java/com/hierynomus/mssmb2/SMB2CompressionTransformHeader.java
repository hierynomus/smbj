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

import java.util.Arrays;

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBHeader;
import com.hierynomus.smbj.common.Check;

/**
 * [MS-SMB2] 2.2.42 SMB2 COMPRESSION_TRANSFORM_HEADER
 * <p>
 * The SMB2 COMPRESSION_TRANSFORM_HEADER is used by the client or server when sending compressed messages.
 * This optional header is only valid for the SMB 3.1.1 dialect&lt;73&gt;.
 */
public class SMB2CompressionTransformHeader implements SMBHeader {
    private static final byte[] COMPRESSED_PROTOCOL_ID = {(byte) 0xFC, 'S', 'M', 'B'};
    private int headerStartPosition;
    private int originalCompressedSegmentSize;
    private SMB3CompressionAlgorithm compressionAlgorithm;
    private int offset;
    private int messageEndPosition;

    @Override
    public void writeTo(SMBBuffer buffer) {

    }

    @Override
    public void readFrom(Buffer<?> buffer) throws Buffer.BufferException {
        this.headerStartPosition = buffer.rpos(); // Keep track of the header start position.
        byte[] protocolId = buffer.readRawBytes(4); // ProtocolId (4 bytes) (already verified)
        Check.ensureEquals(protocolId, COMPRESSED_PROTOCOL_ID, "Could not find SMB2 Packet header");
        this.originalCompressedSegmentSize = buffer.readUInt32AsInt(); // OriginalCompressedSegmentSize (4 bytes)
        this.compressionAlgorithm = EnumWithValue.EnumUtils.valueOf(buffer.readUInt16(), SMB3CompressionAlgorithm.class, null);
        Check.ensure(compressionAlgorithm != null && compressionAlgorithm != SMB3CompressionAlgorithm.NONE, "The CompressionAlgorithm field of the SMB2_COMPRESSION_TRANSFORM_HEADER should contain a valid value.");
        buffer.skip(2);
        this.offset = buffer.readUInt32AsInt(); // Offset (4 bytes)
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

    public int getOriginalCompressedSegmentSize() {
        return originalCompressedSegmentSize;
    }

    public SMB3CompressionAlgorithm getCompressionAlgorithm() {
        return compressionAlgorithm;
    }

    public int getOffset() {
        return offset;
    }

    public static boolean isCompressed(byte[] header) {
        return Arrays.equals(COMPRESSED_PROTOCOL_ID, header);
    }
}
