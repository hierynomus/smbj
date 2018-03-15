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
package com.hierynomus.mssmb2.copy;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 * https://msdn.microsoft.com/en-us/library/cc246549.aspx
 */
public class CopyChunkResponse {
    private long chunksWritten;
    private long chunkBytesWritten;
    private long totalBytesWritten;

    public CopyChunkResponse() {
    }

    public CopyChunkResponse(long chunksWritten, long chunkBytesWritten, long totalBytesWritten) {
        this.chunksWritten = chunksWritten;
        this.chunkBytesWritten = chunkBytesWritten;
        this.totalBytesWritten = totalBytesWritten;
    }

    public long getChunksWritten() {
        return chunksWritten;
    }

    public long getChunkBytesWritten() {
        return chunkBytesWritten;
    }

    public long getTotalBytesWritten() {
        return totalBytesWritten;
    }

    public final void read(SMBBuffer in) throws Buffer.BufferException {
        chunksWritten = in.readUInt32();
        chunkBytesWritten = in.readUInt32();
        totalBytesWritten = in.readUInt32();
    }
}
