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
package com.hierynomus.smbj.share;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.fileinformation.FileEndOfFileInformation;
import com.hierynomus.msfscc.fileinformation.FileStandardInformation;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.mssmb2.copy.CopyChunkRequest;
import com.hierynomus.mssmb2.copy.CopyChunkResponse;
import com.hierynomus.mssmb2.messages.SMB2IoctlResponse;
import com.hierynomus.mssmb2.messages.SMB2ReadResponse;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.io.ByteBufferByteChunkProvider;
import com.hierynomus.smbj.io.ByteChunkProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Future;

public class File extends DiskEntry {

    private final SMB2Writer writer;

    File(SMB2FileId fileId, DiskShare diskShare, SmbPath fileName) {
        super(fileId, diskShare, fileName);
        this.writer = new SMB2Writer(diskShare, fileId, fileName.toUncPath());
    }

    /**
     * Write the data in buffer to this file at position fileOffset.
     *
     * @param buffer     the data to write
     * @param fileOffset The offset, in bytes, into the file to which the data should be written
     * @return the actual number of bytes that was written to the file
     */
    public long write(byte[] buffer, long fileOffset) {
        return writer.write(buffer, fileOffset);
    }

    /**
     * Write the data in buffer to this file at position fileOffset.
     *
     * @param buffer     the data to write
     * @param fileOffset The offset, in bytes, into the file to which the data should be written
     * @param offset     the start offset in the data
     * @param length     the number of bytes that are written
     * @return the actual number of bytes that was written to the file
     */
    public long write(byte[] buffer, long fileOffset, int offset, int length) {
        return writer.write(buffer, fileOffset, offset, length);
    }

    /**
     * Write all available data from the byte chunk provider to this file.
     * The offset in the file to which data is written is determined by {@link ByteChunkProvider#getOffset()}.
     *
     * @param provider the byte chunk provider
     * @return the actual number of bytes that was written to the file
     */
    public long write(ByteChunkProvider provider) {
        return writer.write(provider);
    }

    /**
     * Write all available data from the byte chunk provider to this file.
     * The offset in the file to which data is written is determined by {@link ByteChunkProvider#getOffset()}.
     *
     * @param provider         the byte chunk provider
     * @param progressListener an optional callback that will be invoked when data has been written to the file
     * @return the actual number of bytes that was written to the file
     */
    public long write(ByteChunkProvider provider, ProgressListener progressListener) {
        return writer.write(provider, progressListener);
    }

    /***
     * Write the data Async in buffer to this file at position fileOffset.
     * @param buffer     the data to write
     * @param fileOffset The offset, in bytes, into the file to which the data should be written
     * @param offset     the start offset in the data
     * @param length     the number of bytes that are written
     * @return A Future containing the total number of bytes written to the remote.
     */
    public Future<Long> writeAsync(byte[] buffer, long fileOffset, int offset, int length) {
        return writer.writeAsync(buffer, fileOffset, offset, length);
    }

    /**
     * Async Write all available data from the byte chunk provider to this file.
     * The offset in the file to which data is written is determined by {@link ByteChunkProvider#getOffset()}.
     *
     * @param provider the byte chunk provider
     * @return A future containing the total number of bytes written to the remote.
     */
    public Future<Long> writeAsync(ByteChunkProvider provider) {
        return writer.writeAsync(provider);
    }

    public OutputStream getOutputStream() {
        return getOutputStream(false);
    }

    public OutputStream getOutputStream(boolean append) {
        return getOutputStream(null, append);
    }

    public OutputStream getOutputStream(ProgressListener listener) {
        return getOutputStream(listener, false);
    }

    public OutputStream getOutputStream(ProgressListener listener, boolean append) {
        return writer.getOutputStream(listener, append ? getFileInformation(FileStandardInformation.class).getEndOfFile() : 0l);
    }

    /**
     * Read data from this file starting at position fileOffset into the given buffer.
     *
     * @param buffer     the buffer to write into
     * @param fileOffset The offset, in bytes, into the file from which the data should be read
     * @return the actual number of bytes that were read; or -1 if the end of the file was reached
     */
    public int read(byte[] buffer, long fileOffset) {
        return read(buffer, fileOffset, 0, buffer.length);
    }

    /**
     * Read data from this file starting at position fileOffset into the given buffer.
     *
     * @param buffer     the buffer to write into
     * @param fileOffset The offset, in bytes, into the file from which the data should be read
     * @param offset     the start offset in the buffer at which to write data
     * @param length     the maximum number of bytes to read
     * @return the actual number of bytes that were read; or -1 if the end of the file was reached
     */
    public int read(byte[] buffer, long fileOffset, int offset, int length) {
        SMB2ReadResponse response = share.read(fileId, fileOffset, length);
        if (response.getHeader().getStatusCode() == NtStatus.STATUS_END_OF_FILE.getValue()) {
            return -1;
        } else {
            byte[] data = response.getData();
            int bytesRead = Math.min(length, data.length);
            System.arraycopy(data, 0, buffer, offset, bytesRead);
            return bytesRead;
        }
    }

    Future<SMB2ReadResponse> readAsync(long offset, int length) {
        return share.readAsync(fileId, offset, length);
    }

    public void read(OutputStream destStream) throws IOException {
        read(destStream, null);
    }

    public void read(OutputStream destStream, ProgressListener progressListener) throws IOException {
        InputStream is = getInputStream(progressListener);
        int numRead;
        byte[] buf = new byte[share.getReadBufferSize()];
        while ((numRead = is.read(buf)) != -1) {
            destStream.write(buf, 0, numRead);
        }
        is.close();
    }

    /**
     * Write the data in a {@link ByteBuffer} to this file at position fileOffset.
     *
     * @param buffer     the data to write
     * @param fileOffset The offset, in bytes, into the file to which the data should be written
     * @return the actual number of bytes that was written to the file
     */
    public int write(ByteBuffer buffer, long fileOffset) {
        ByteChunkProvider provider = new ByteBufferByteChunkProvider(buffer, fileOffset);
        // size of a ByteBuffer is represented by an int, so this cannot be higher than that
        return (int)write(provider);
    }


    /**
     * Read data from this file starting at position fileOffset into the given {@link ByteBuffer}.
     *
     * @param buffer     the {@link ByteBuffer} to write into
     * @param fileOffset The offset, in bytes, into the file from which the data should be read
     * @return the actual number of bytes that were read; or -1 if the end of the file was reached
     */
    public int read(ByteBuffer buffer, long fileOffset) {
        int remaining = buffer.remaining();

        SMB2ReadResponse response = share.read(fileId, fileOffset, remaining);
        if (response.getHeader().getStatusCode() == NtStatus.STATUS_END_OF_FILE.getValue()) {
            return -1;
        } else {
            byte[] data = response.getData();
            int bytesRead = Math.min(remaining, data.length);
            buffer.put(data, 0, bytesRead);
            return bytesRead;
        }
    }

    /**
     * Performs a remote file copy of this file to the given file.
     * <p>
     * This method is equivalent to calling {@link #remoteCopyTo(File) remoteCopyTo(0, destination, 0, sourceFileSize)}.
     *
     * @param destination the destination file
     */
    public void remoteCopyTo(File destination) throws Buffer.BufferException, TransportException {
        if (destination.share != share) {
            throw new SMBRuntimeException("Remote copy is only possible between files on the same server");
        }

        long fileSize = getFileInformation(FileStandardInformation.class).getEndOfFile();
        remoteCopyTo(0, destination, 0, fileSize);
    }

    /**
     * Copies the byte range <code>[offset, length]</code> of this file to the range <code>[destinationOffset, length]</code>
     * of the given destination file.
     *
     * @param destination the destination file
     */
    public void remoteCopyTo(long offset, File destination, long destinationOffset, long length) throws Buffer.BufferException, TransportException {
        if (destination.share != share) {
            throw new SMBRuntimeException("Remote copy is only possible between files on the same server");
        }

        remoteFileCopy(this, offset, destination, destinationOffset, length);
    }

    /**
     * Remote copy logic as described in https://msdn.microsoft.com/en-us/library/cc246475.aspx
     */
    private static void remoteFileCopy(File source, long sourceOffset, File destination, long destinationOffset, long length) throws Buffer.BufferException, TransportException {
        byte[] resumeKey = source.getResumeKey();

        // Somewhat arbitrary defaults. If these exceed the server limitations STATUS_INVALID_PARAMETER will
        // be returned and the parameters will be adjusted.
        long maxChunkSize = 1024L * 1024;
        long maxChunkCount = 16;
        long maxRequestSize = maxChunkCount * maxChunkSize;

        long srcOff = sourceOffset;
        long dstOff = destinationOffset;
        long remaining = length;

        while (remaining > 0) {
            CopyChunkRequest request = new CopyChunkRequest(
                resumeKey,
                createCopyChunks(srcOff, dstOff, remaining, maxChunkCount, maxChunkSize, maxRequestSize)
            );

            SMB2IoctlResponse ioctlResponse = copyChunk(source.share, destination, request);

            CopyChunkResponse response = new CopyChunkResponse();
            response.read(new SMBBuffer(ioctlResponse.getOutputBuffer()));

            long status = ioctlResponse.getHeader().getStatusCode();
            // See <a href="https://msdn.microsoft.com/en-us/library/cc246549.aspx">[MS-SMB2] 2.2.32.1 SRV_COPYCHUNK_RESPONSE</a>.
            if (status == NtStatus.STATUS_INVALID_PARAMETER.getValue()) {
                // If the Status field in the SMB2 header of the response is STATUS_INVALID_PARAMETER:
                //   ChunksWritten indicates the maximum number of chunks that the server will accept in a single request.
                //   ChunkBytesWritten indicates the maximum number of bytes the server will allow to be written in a single chunk.
                //   TotalBytesWritten indicates the maximum number of bytes the server will accept to copy in a single request.
                maxChunkCount = response.getChunksWritten();
                long maxSizePerChunk = response.getChunkBytesWritten();
                long maxSizePerRequest = response.getTotalBytesWritten();
                maxChunkSize = Math.min(maxSizePerChunk, maxSizePerRequest);
            } else {
                // Otherwise:
                //   ChunksWritten indicates the number of chunks that were successfully written.
                //   ChunkBytesWritten indicates the number of bytes written in the last chunk that did not successfully process (if a partial write occurred).
                //   TotalBytesWritten indicates the total number of bytes written in the server-side copy operation.
                long bytesWritten = response.getTotalBytesWritten();
                srcOff += bytesWritten;
                dstOff += bytesWritten;
                remaining -= bytesWritten;
            }
        }
    }

    private static final int FSCTL_SRV_REQUEST_RESUME_KEY = 0x00140078;

    /**
     * See [MS-SMB2] 2.2.32.3 SRV_REQUEST_RESUME_KEY Response
     * https://msdn.microsoft.com/en-us/library/cc246804.aspx
     */
    private byte[] getResumeKey() throws Buffer.BufferException {
        byte[] response = ioctl(FSCTL_SRV_REQUEST_RESUME_KEY, true, new byte[0], 0, 0, 32);
        return Arrays.copyOf(response, 24);
    }

    /**
     * Creates the list of copy chunks to copy <code>length</code> bytes from <code>srcOffset</code> to <code>dstOffset</code>
     *
     * @param srcOffset      the source file offset at which to start reading
     * @param dstOffset      the destination file offset at which to start writing
     * @param length         the total number of bytes to copy
     * @param maxChunkCount  the maximum number of chunks that may be create
     * @param maxChunkSize   the maximum size of each individual chunk
     * @param maxRequestSize the maximum total size of all chunks combined
     * @return a list of copy chunks
     */
    private static List<CopyChunkRequest.Chunk> createCopyChunks(long srcOffset, long dstOffset, long length, long maxChunkCount, long maxChunkSize, long maxRequestSize) {
        List<CopyChunkRequest.Chunk> chunks = new ArrayList<>();

        long remaining = length;
        int chunkCount = 0;
        int totalSize = 0;
        long srcOff = srcOffset;
        long dstOff = dstOffset;

        while (remaining > 0 && chunkCount < maxChunkCount && totalSize < maxRequestSize) {
            long chunkSize = Math.min(remaining, maxChunkSize);

            chunks.add(new CopyChunkRequest.Chunk(
                srcOff,
                dstOff,
                chunkSize)
            );

            chunkCount++;
            totalSize += chunkSize;
            srcOff += chunkSize;
            dstOff += chunkSize;
            remaining -= chunkSize;
        }

        return chunks;
    }

    private static final StatusHandler COPY_CHUNK_ALLOWED_STATUS_VALUES = new StatusHandler() {
        @Override
        public boolean isSuccess(long statusCode) {
            return statusCode == NtStatus.STATUS_SUCCESS.getValue() || statusCode == NtStatus.STATUS_INVALID_PARAMETER.getValue();
        }
    };

    /**
     * See [MS-SMB2] 2.2.31.1.1 SRV_COPYCHUNK
     * https://msdn.microsoft.com/en-us/library/cc246546.aspx
     */
    private static SMB2IoctlResponse copyChunk(Share share, File target, CopyChunkRequest request) {
        SMBBuffer buffer = new SMBBuffer();
        request.write(buffer);
        byte[] data = buffer.getCompactData();

        SMB2IoctlResponse response = share.receive(
            share.ioctlAsync(target.fileId, CopyChunkRequest.getCtlCode(), true, new ArrayByteChunkProvider(data, 0, data.length, 0), 12),
            "IOCTL",
            target.fileId,
            COPY_CHUNK_ALLOWED_STATUS_VALUES,
            share.getReadTimeout()
        );

        if (response.getError() != null) {
            throw new SMBApiException(response.getHeader(), "FSCTL_SRV_COPYCHUNK failed");
        }

        return response;
    }

    /**
     * Returns the length of the file.
     *
     * @return the length of the file.
     * @throws SMBApiException if an error occurs.
     */
    public long getLength() throws SMBApiException {
        return getFileInformation(FileStandardInformation.class).getEndOfFile();
    }

    /***
     * The function for truncate or set file length for a file
     * @param endOfFile 64-bit signed integer in bytes, MUST be greater than or equal to 0
     * @throws SMBApiException
     */
    public void setLength(long endOfFile) throws SMBApiException {
        FileEndOfFileInformation endOfFileInfo = new FileEndOfFileInformation(endOfFile);
        this.setFileInformation(endOfFileInfo);
    }

    public InputStream getInputStream() {
        return getInputStream(null);
    }

    public InputStream getInputStream(ProgressListener listener) {
        return new FileInputStream(this, share.getReadBufferSize(), share.getReadTimeout(), listener);
    }

    @Override
    public String toString() {
        return "File{" +
            "fileId=" + fileId +
            ", fileName='" + name.toUncPath() + '\'' +
            '}';
    }

}
