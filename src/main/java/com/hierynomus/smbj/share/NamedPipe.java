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

import com.hierynomus.msfscc.fsctl.FsCtlPipePeekResponse;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2ReadResponse;
import com.hierynomus.mssmb2.messages.SMB2WriteResponse;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;

public class NamedPipe implements Closeable {
    private static final long FSCTL_PIPE_PEEK = 0x0011400cL;
    private static final long FSCTL_PIPE_TRANSCEIVE = 0x0011c017L;

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    protected PipeShare share;
    protected SMB2FileId fileId;
    protected String name;

    NamedPipe(SMB2FileId fileId, PipeShare share, String name) {
        this.share = share;
        this.fileId = fileId;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    /**
     * Write the data in buffer to this pipe.
     *
     * @param buffer the data to write
     * @return the actual number of bytes that was written to the file
     */
    public int write(byte[] buffer) {
        return write(buffer, 0, buffer.length);
    }

    /**
     * Write the data in buffer to this pipe.
     *
     * @param buffer the data to write
     * @param offset the start offset in the data
     * @param length the number of bytes that are written
     * @return the actual number of bytes that was written to the file
     */
    public int write(byte[] buffer, int offset, int length) {
        ArrayByteChunkProvider provider = new ArrayByteChunkProvider(buffer, offset, length, 0);
        logger.debug("Writing to {} from offset {}", this.name, provider.getOffset());
        SMB2WriteResponse wresp = share.write(fileId, provider);
        return (int) wresp.getBytesWritten();
    }

    /**
     * Read data from this pipe starting into the given buffer.
     *
     * @param buffer the buffer to write into
     * @return the actual number of bytes that were read
     */
    public int read(byte[] buffer) {
        return read(buffer, 0, buffer.length);
    }

    /**
     * Read data from this pipe into the given buffer.
     *
     * @param buffer the buffer to write into
     * @param offset the start offset in the buffer at which to write data
     * @param length the maximum number of bytes to read
     * @return the actual number of bytes that were read
     */
    public int read(byte[] buffer, int offset, int length) {
        SMB2ReadResponse response = share.read(fileId, 0, length);
        byte[] data = response.getData();
        int bytesRead = Math.min(length, data.length);
        System.arraycopy(data, 0, buffer, offset, bytesRead);
        return bytesRead;
    }

    /**
     * Performs a transaction on this pipe. This combines the writing a message to and reading a message from this
     * pipe into a single network operation.
     *
     * @param inBuffer the input message
     * @return the output message
     */
    public byte[] transact(byte[] inBuffer) {
        return ioctl(FSCTL_PIPE_TRANSCEIVE, true, inBuffer, 0, inBuffer.length);
    }

    /**
     * Performs a transaction on this pipe. This combines the writing a message to and reading a message from this
     * pipe into a single network operation.
     * <p>
     * This method is equivalent to calling {@link #transact(byte[], int, int, byte[], int, int) transact(inBuffer, 0, inBuffer.length, outBuffer, 0, outBuffer.length}.
     *
     * @param inBuffer  the input message
     * @param outBuffer the buffer in which to write the output message
     * @return the number of bytes written to <code>outBuffer</code>
     */
    public int transact(byte[] inBuffer, byte[] outBuffer) {
        return transact(inBuffer, 0, inBuffer.length, outBuffer, 0, outBuffer.length);
    }

    /**
     * Performs a transaction on this pipe. This combines the writing a message to and reading a message from this
     * pipe into a single network operation.
     *
     * @param inBuffer  the input message
     * @param inOffset  the offset in <code>inBuffer</code> at which the input message start
     * @param inLength  the length of the input message in <code>inBuffer</code> starting at <code>inOffset</code>
     * @param outBuffer the buffer in which to write the output message
     * @param outOffset the offset in <code>outBuffer</code> at which the output message should be written
     * @param outLength the maximum number of bytes that may be written to <code>outBuffer</code> starting from <code>outOffset</code>
     * @return the number of bytes written to <code>outBuffer</code>
     */
    public int transact(byte[] inBuffer, int inOffset, int inLength, byte[] outBuffer, int outOffset, int outLength) {
        return ioctl(FSCTL_PIPE_TRANSCEIVE, true, inBuffer, inOffset, inLength, outBuffer, outOffset, outLength);
    }

    /**
     * Requests that the server read data from this pipe without removing it.
     * This method is equivalent to calling {@link #peek(int) peek(0)}.
     *
     * @return the peek response
     */
    public FsCtlPipePeekResponse peek() {
        return peek(0);
    }

    /**
     * Requests that the server read data from this pipe without removing it.
     *
     * @param maxDataSize the maximum amount of data to peek
     * @return the peek response
     */
    public FsCtlPipePeekResponse peek(int maxDataSize) {
        byte[] output = share.ioctl(
            fileId,
            FSCTL_PIPE_PEEK, true,
            null, 0, 0,
            FsCtlPipePeekResponse.STRUCTURE_SIZE + maxDataSize
        );

        try {
            SMBBuffer buffer = new SMBBuffer(output);
            FsCtlPipePeekResponse peekResponse = new FsCtlPipePeekResponse();
            peekResponse.read(buffer);
            return peekResponse;
        } catch (Buffer.BufferException e) {
            throw new SMBRuntimeException(e);
        }
    }

    /**
     * Sends a control code directly to a specified device driver, causing the corresponding device to perform the
     * corresponding operation.
     *
     * @param ctlCode  the control code
     * @param isFsCtl  true if the control code is an FSCTL; false if it is an IOCTL
     * @param inData   the control code dependent input data
     * @param inOffset the offset in <code>inData</code> where the input data starts
     * @param inLength the number of bytes from <code>inData</code> to send, starting at <code>offset</code>
     * @return the response data or <code>null</code> if the control code did not produce a response
     */
    public byte[] ioctl(long ctlCode, boolean isFsCtl, byte[] inData, int inOffset, int inLength) {
        return share.ioctl(fileId, ctlCode, isFsCtl, inData, inOffset, inLength);
    }

    /**
     * Sends a control code directly to a specified device driver, causing the corresponding device to perform the
     * corresponding operation.
     *
     * @param ctlCode   the control code
     * @param isFsCtl   true if the control code is an FSCTL; false if it is an IOCTL
     * @param inData    the control code dependent input data
     * @param inOffset  the offset in <code>inData</code> where the input data starts
     * @param inLength  the number of bytes from <code>inData</code> to send, starting at <code>inOffset</code>
     * @param outData   the buffer where the response data should be written
     * @param outOffset the offset in <code>outData</code> where the output data should be written
     * @param outLength the maximum amount of data to write in <code>outData</code>, starting at <code>outOffset</code>
     * @return the number of bytes written to <code>outData</code>
     */
    public int ioctl(long ctlCode, boolean isFsCtl, byte[] inData, int inOffset, int inLength, byte[] outData, int outOffset, int outLength) {
        return share.ioctl(fileId, ctlCode, isFsCtl, inData, inOffset, inLength, outData, outOffset, outLength);
    }

    public void close() {
        share.closeFileId(fileId);
    }

    public void closeSilently() {
        try {
            close();
        } catch (Exception e) {
            logger.warn("Pipe close failed for {},{},{}", name, share, fileId, e);
        }
    }
}
