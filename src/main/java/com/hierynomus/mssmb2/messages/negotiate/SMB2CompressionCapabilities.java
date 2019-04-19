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

import com.hierynomus.mssmb2.SMB3CompressionAlgorithm;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.util.ArrayList;
import java.util.List;

/**
 * [MS-SMB2].pdf 2.2.3.1.3 / 2.2.4.1.3 SMB2_COMPRESSION_CAPABILITIES Request / Response
 */
public class SMB2CompressionCapabilities extends SMB2NegotiateContext {

    private List<SMB3CompressionAlgorithm> compressionAlgorithms;

    SMB2CompressionCapabilities() {
        super(SMB2NegotiateContextType.SMB2_COMPRESSION_CAPABILITIES);
        this.compressionAlgorithms = new ArrayList<>();
    }

    SMB2CompressionCapabilities(List<SMB3CompressionAlgorithm> compressionAlgorithms) {
        super(SMB2NegotiateContextType.SMB2_COMPRESSION_CAPABILITIES);
        this.compressionAlgorithms = compressionAlgorithms;
    }

    @Override
    protected int writeContext(SMBBuffer buffer) {
        if (compressionAlgorithms == null) {
            throw new IllegalStateException("Cannot write a null compressionAlgorithms array");
        }
        buffer.putUInt16(compressionAlgorithms.size()); // CompressionAlgorithmCount (2 bytes)
        buffer.putReserved2(); // Padding (2 bytes)
        buffer.putReserved4(); // Reserved (4 bytes)
        for (SMB3CompressionAlgorithm compressionAlgorithm : compressionAlgorithms) {
            buffer.putUInt16((int) compressionAlgorithm.getValue()); // CompresisonAlgorithm (2 bytes)
        }
        return 8 + 2 * compressionAlgorithms.size();
    }

    @Override
    protected void readContext(SMBBuffer buffer, int dataSize) throws Buffer.BufferException {
        int compressionAlgorithmCount = buffer.readUInt16(); // CompressionAlgorithmCount (2 bytes)
        buffer.skip(2); // Padding (2 bytes)
        buffer.skip(4); // Reserved (4 bytes)
        for (int i = 0; i < compressionAlgorithmCount; i++) {
            compressionAlgorithms.add(EnumWithValue.EnumUtils.valueOf(buffer.readUInt16(), SMB3CompressionAlgorithm.class, null));
        }
    }
}
