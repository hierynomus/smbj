package com.hierynomus.smbj.share;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.copy.*;
import com.hierynomus.mssmb2.messages.SMB2IoctlResponse;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;

import java.util.EnumSet;

/**
 *
 */
public class FileCopy {

    private long chunk_max_size = 1 * 1024 * 1024;
    private long chunk_limit_in_request = 256;
    private File source;
    private File target;
    private Share share;

    public FileCopy(File source, File target, Share share) {
        this.source = source;
        this.target = target;
        this.share = share;
    }

    //Implemented based on https://msdn.microsoft.com/en-us/library/cc246475.aspx
    public void run() throws Buffer.BufferException, TransportException {
        ResumeKeyRequest resumeKeyRequest = new ResumeKeyRequest();
        byte[] bytes = source.ioctl((int) ResumeKeyRequest.getCtlCode(), true, resumeKeyRequest.getData(), 0, resumeKeyRequest.getData().length);
        ResumeKeyResponse resumeKeyResponse = Converter.decodeResumeKey(bytes);
        long sourceFileSize = getFileSize(source);
        int chunkCount = getNumberOfChunks(sourceFileSize, chunk_max_size);
        int currentChunk = 0;
        EnumSet<NtStatus> ntStatuses = getSuccessStatuses(share);
        CopyChunkRequest request = new CopyChunkRequest(resumeKeyResponse.getResumeKey());
        do {
            request.getChunks().add(new CopyChunkRequest.Chunk(chunk_max_size * currentChunk,chunk_max_size * currentChunk, calculateChunkLength(sourceFileSize, currentChunk, chunk_max_size)));
            currentChunk++;
            if (currentChunk % chunk_limit_in_request == 0 || currentChunk==chunkCount){
                SMB2IoctlResponse response = send(target, share, ntStatuses, request);
                CopyChunkResponse chunkResponse = Converter.decodeCopyChunkResponse(response.getOutputBuffer());
                if (response.getHeader().getStatus() == NtStatus.STATUS_INVALID_PARAMETER){
                    //handle max limites for one request and start from scratch
                    handleMaxLimits(chunkResponse);
                    currentChunk=0;
                } else {
                  //can be added progresslistener
                }
                //reuse same object
                request.getChunks().clear();
            }
        } while (currentChunk < chunkCount);
    }

    private long calculateChunkLength(long sourceFileSize, int currentChunk, long chunk_max_size) {
        return Math.min(chunk_max_size, sourceFileSize - (currentChunk * chunk_max_size));
    }

    /**
     * https://msdn.microsoft.com/en-us/library/cc246549.aspx
     *
     * Modify maxLimits based on server's response
     * @param chunkResponse
     */
    private void handleMaxLimits(CopyChunkResponse chunkResponse)  {
        //see page above for details
        chunk_limit_in_request = chunkResponse.getChunksWritten();
        this.chunk_max_size = chunkResponse.getChunkBytesWritten();
        long maxBytes = chunkResponse.getTotalBytesWritten();
        this.chunk_limit_in_request = Math.min(chunk_limit_in_request,maxBytes/ chunk_max_size);
    }

    private SMB2IoctlResponse send(File target, Share share, EnumSet<NtStatus> ntStatuses, CopyChunkRequest request) {
        byte[] data = Converter.encodeCopyChunkRequest(request);
        return share.receive(
                            share.ioctlAsync(target.fileId, CopyChunkRequest.getCtlCode(), true, new ArrayByteChunkProvider(data, 0, data.length, 0), -1),
                            "IOCTL",
                            target.fileId,
                            ntStatuses,
                            share.getReadTimeout()
                        );
    }

    /**
     * Build Success statuses
     * https://msdn.microsoft.com/en-us/library/cc246549.aspx
     * Status Invalid Parameter is also acceptable as we had to react for maximums server supports
     * @param share
     * @return
     */
    private EnumSet<NtStatus> getSuccessStatuses(Share share) {
        EnumSet<NtStatus> ntStatuses = EnumSet.copyOf(share.getCreateSuccessStatus());
        ntStatuses.add(NtStatus.STATUS_INVALID_PARAMETER);
        return ntStatuses;
    }

    private int getNumberOfChunks(long sourceFileSize, long chunkMaxSize) {
        return (int) Math.ceil(sourceFileSize / (double) chunkMaxSize);
    }

    private long getFileSize(File source) throws TransportException {
        return source.getFileInformation().getStandardInformation().getEndOfFile();
    }
}
