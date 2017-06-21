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

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2ReadResponse;
import com.hierynomus.mssmb2.messages.SMB2WriteResponse;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.smbj.io.ByteChunkProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.Future;

public class File extends DiskEntry {

    private static final Logger logger = LoggerFactory.getLogger(File.class);

    File(SMB2FileId fileId, DiskShare diskShare, String fileName) {
        super(diskShare, fileId, fileName);
    }

    /**
     * Write the data in buffer to this file at position fileOffset.
     * @param buffer the data to write
     * @param fileOffset The offset, in bytes, into the file to which the data should be written
     * @return the actual number of bytes that was written to the file
     */
    public int write(byte[] buffer, long fileOffset) throws IOException {
        return write(buffer, fileOffset, 0, buffer.length);
    }

    /**
     * Write the data in buffer to this file at position fileOffset.
     * @param buffer the data to write
     * @param fileOffset The offset, in bytes, into the file to which the data should be written
     * @param offset the start offset in the data
     * @param length the number of bytes that are written
     * @return the actual number of bytes that was written to the file
     */
    public int write(byte[] buffer, long fileOffset, int offset, int length) throws IOException {
        return write(new ArrayByteChunkProvider(buffer, offset, length, fileOffset), null);
    }

    /**
     * Write all available data from the byte chunk provider to this file.
     * The offset in the file to which data is written is determined by {@link ByteChunkProvider#getOffset()}.
     * @param provider the byte chunk provider
     * @return the actual number of bytes that was written to the file
     */
    public int write(ByteChunkProvider provider) throws IOException {
        return write(provider, null);
    }

    /**
     * Write all available data from the byte chunk provider to this file.
     * The offset in the file to which data is written is determined by {@link ByteChunkProvider#getOffset()}.
     * @param provider the byte chunk provider
     * @param progressListener an optional callback that will be invoked when data has been written to the file
     * @return the actual number of bytes that was written to the file
     */
    public int write(ByteChunkProvider provider, ProgressListener progressListener) {
        int bytesWritten = 0;
        while (provider.isAvailable()) {
            logger.debug("Writing to {} from offset {}", this.fileName, provider.getOffset());
            SMB2WriteResponse wresp = share.write(fileId, provider);
            bytesWritten += wresp.getBytesWritten();
            if (progressListener != null) progressListener.onProgressChanged(wresp.getBytesWritten(), provider.getOffset());
        }
        return bytesWritten;
    }

    public OutputStream getOutputStream() {
        return getOutputStream(null);
    }

    public OutputStream getOutputStream(ProgressListener listener) {
        return new FileOutputStream(
            this,
            share.getWriteBufferSize(),
            listener
        );
    }

    /**
     * Read data from this file starting at position fileOffset into the given buffer.
     * @param buffer the buffer to write into
     * @param fileOffset The offset, in bytes, into the file from which the data should be read
     * @return the actual number of bytes that were read
     */
    public int read(byte[] buffer, long fileOffset) throws IOException {
        return read(buffer, fileOffset, 0, buffer.length);
    }

    /**
     * Read data from this file starting at position fileOffset into the given buffer.
     * @param buffer the buffer to write into
     * @param fileOffset The offset, in bytes, into the file from which the data should be read
     * @param offset the start offset in the buffer at which to write data
     * @param length the maximum number of bytes to read
     * @return the actual number of bytes that were read
     */
    public int read(byte[] buffer, long fileOffset, int offset, int length) throws IOException {
        SMB2ReadResponse response = share.read(fileId, fileOffset, length);
        byte[] data = response.getData();
        int bytesRead = Math.min(length, data.length);
        System.arraycopy(data, 0, buffer, offset, bytesRead);
        return bytesRead;
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

    public InputStream getInputStream() {
        return getInputStream(null);
    }

    public InputStream getInputStream(ProgressListener listener) {
        return new FileInputStream(this, share.getReadBufferSize(), share.getReadTimeout(), listener);
    }

    Future<SMB2ReadResponse> readAsync(long offset, int length) {
        return share.readAsync(fileId, offset, length);
    }

    @Override
    public String toString() {
        return "File{" +
            "fileId=" + fileId +
            ", fileName='" + fileName + '\'' +
            '}';
    }

    private static class ArrayByteChunkProvider extends ByteChunkProvider {

        private final byte[] data;
        private int bufferOffset;
        private int remaining;

        ArrayByteChunkProvider(byte[] data, int offset, int length, long fileOffset) {
            this.data = data;
            this.offset = fileOffset;
            this.bufferOffset = offset;
            this.remaining = length;
        }

        @Override
        public boolean isAvailable() {
            return remaining > 0;
        }

        @Override
        protected int getChunk(byte[] chunk) throws IOException {
            int write = chunk.length;
            if (write > remaining) {
                write = remaining;
            }
            System.arraycopy(data, bufferOffset, chunk, 0, write);
            bufferOffset += write;
            remaining -= write;

            return write;
        }

        @Override
        public int bytesLeft() {
            return remaining;
        }
    }
}
