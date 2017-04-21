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

import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.Future;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2WriteRequest;
import com.hierynomus.mssmb2.messages.SMB2WriteResponse;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.io.ByteChunkProvider;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;

public class FileOutputStream extends OutputStream {

    private TreeConnect treeConnect;
    private SMB2FileId fileId;
    private Session session;
    private Connection connection;
    private int maxWriteSize;
    private ProgressListener progressListener;
    private boolean isClosed = false;
    private ByteArrayProvider provider;

    private static final Logger logger = LoggerFactory.getLogger(FileOutputStream.class);

    public FileOutputStream(File file, ProgressListener progressListener) {
        this.treeConnect = file.treeConnect;
        this.fileId = file.fileId;
        this.session = treeConnect.getSession();
        this.connection = session.getConnection();
        this.progressListener = progressListener;
        this.maxWriteSize = connection.getNegotiatedProtocol().getMaxWriteSize();
        this.provider = new ByteArrayProvider(this.maxWriteSize);
    }

    @Override
    public void write(int b) throws IOException {
        verifyConnectionNotClosed();

        if (provider.isBufferFull()) {
            flush();
        }

        if (!provider.isBufferFull()) {
            provider.writeByte(b);
        }
    }

    @Override
    public void write(byte b[]) throws IOException {
        write(b, 0, b.length);
    }

    @Override
    public void write(byte b[], int off, int len) throws IOException {
        verifyConnectionNotClosed();

        while (provider.isBufferFull(len)) {
            flush();
        }

        if (!provider.isBufferFull()) {
            provider.writeBytes(b, off, len);
        }

    }

    @Override
    public void flush() throws IOException {
        verifyConnectionNotClosed();
        if (provider.isAvailable()) {
            sendWriteRequest();
        }
    }

    private void sendWriteRequest() throws TransportException {
        SMB2WriteRequest wreq = new SMB2WriteRequest(connection.getNegotiatedProtocol().getDialect(), fileId,
            session.getSessionId(), treeConnect.getTreeId(), provider, connection.getNegotiatedProtocol().getMaxWriteSize());
        logger.trace("Sending {} for file {}, byte offset {}, bytes available {}", wreq, treeConnect.getHandle().smbPath, provider.getOffset(), provider.bytesLeft());
        Future<SMB2WriteResponse> writeFuture = session.send(wreq);
        SMB2WriteResponse wresp = Futures.get(writeFuture, TransportException.Wrapper);
        if (wresp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(wresp.getHeader(), "Write failed for " + this);
        }
        if (progressListener != null) {
            progressListener.onProgressChanged(wresp.getBytesWritten(), provider.getOffset());
        }
    }

    @Override
    public void close() throws IOException {

        while (provider.isAvailable()) {
            sendWriteRequest();
        }

        provider.reset();

        isClosed = true;
        treeConnect = null;
        session = null;
        connection = null;
        logger.debug("EOF, {} bytes written", provider.getOffset());
    }

    private void verifyConnectionNotClosed() throws IOException {
        if (isClosed) throw new IOException("Stream is closed");
    }

    private static class ByteArrayProvider extends ByteChunkProvider {

        private RingBuffer buf;

        private ByteArrayProvider(int maxWriteSize) {
            this.buf = new RingBuffer(maxWriteSize);
        }

        @Override
        public boolean isAvailable() {
            return !buf.isEmpty();
        }

        @Override
        protected int getChunk(byte[] chunk) throws IOException {
            return buf.read(chunk);
        }

        @Override
        public int bytesLeft() {
            return buf.size();
        }

        public void writeBytes(byte[] b, int off, int len) {
            buf.write(b, off, len);
        }

        public void writeByte(int b) {
            buf.write(b);
        }

        public boolean isBufferFull() {
            return buf.isFull();
        }

        public boolean isBufferFull(int len) {
            return buf.isFull(len);
        }

        private void reset() {
            this.buf = null;
        }
    }
}
