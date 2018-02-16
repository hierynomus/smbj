package com.hierynomus.mssmb2.copy;

import java.util.ArrayList;
import java.util.List;

/**
 * https://msdn.microsoft.com/en-us/library/cc246547.aspx
 */
public class CopyChunkRequest {
    private static final long ctlCode = 0x001480F2l;

    private byte[] resumeKey;
    private List<Chunk> chunks = new ArrayList<>();

    public CopyChunkRequest(byte[] resumeKey) {
        this.resumeKey = resumeKey;
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
