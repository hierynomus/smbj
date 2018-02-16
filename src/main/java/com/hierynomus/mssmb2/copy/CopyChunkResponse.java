package com.hierynomus.mssmb2.copy;

/**
 *https://msdn.microsoft.com/en-us/library/cc246549.aspx
 */
public class CopyChunkResponse {
    private long chunksWritten;
    private long chunkBytesWritten;
    private long totalBytesWritten;

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
}
