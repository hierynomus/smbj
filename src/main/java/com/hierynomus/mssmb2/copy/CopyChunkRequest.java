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

import com.hierynomus.smb.SMBBuffer;

import java.util.ArrayList;
import java.util.List;

/**
 * https://msdn.microsoft.com/en-us/library/cc246547.aspx
 */
public class CopyChunkRequest {
    private static final long ctlCode = 0x001480F2l;

    private byte[] resumeKey;
    private List<Chunk> chunks = new ArrayList<>();

    public CopyChunkRequest(byte[] resumeKey, List<Chunk> chunks) {
        this.resumeKey = resumeKey;
        this.chunks.addAll(chunks);
    }

    public static long getCtlCode() {
        return ctlCode;
    }

    public byte[] getResumeKey() {
        return resumeKey;
    }

    public List<Chunk> getChunks() {
        return chunks;
    }

    public void write(SMBBuffer buffer) {
        buffer.putRawBytes(getResumeKey());  //RESUME KEY
        buffer.putUInt32(getChunks().size());    //CHUNK COUNT
        buffer.putUInt32(0l);    //reserved
        for (CopyChunkRequest.Chunk chunk : getChunks()){
            buffer.putUInt64(chunk.getSrcOffset());//source offset
            buffer.putUInt64(chunk.getTgtOffset());//target offset
            buffer.putUInt32(chunk.getLength()); //length
            buffer.putUInt32(0); //reserved 0 always
        }
    }

    /**
     *https://msdn.microsoft.com/en-us/library/cc246546.aspx
     */
    public static final class Chunk {
        private long srcOffset;
        private long tgtOffset;
        private long length;

        public Chunk(long srcOffset, long tgtOffset, long length) {
            this.srcOffset = srcOffset;
            this.tgtOffset = tgtOffset;
            this.length = length;
        }

        public long getSrcOffset() {
            return srcOffset;
        }

        public long getTgtOffset() {
            return tgtOffset;
        }

        public long getLength() {
            return length;
        }
    }
}
