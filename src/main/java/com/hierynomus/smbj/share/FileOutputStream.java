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
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2WriteRequest;
import com.hierynomus.mssmb2.messages.SMB2WriteResponse;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.io.ByteChunkProvider;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.Future;

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

        if (provider.getCurrentSize() < maxWriteSize) {
            provider.getBuf()[provider.getCurrentSize()] = (byte) b;
            provider.incCurrentSize();
        }
        if (provider.getCurrentSize() == maxWriteSize) flush();
    }

    @Override
    public void write(byte b[]) throws IOException {
        write(b, 0, b.length);
    }

    @Override
    public void write(byte b[], int off, int len) throws IOException {
        verifyConnectionNotClosed();
        if (provider.getCurrentSize() < maxWriteSize) {
            System.arraycopy(b, off, provider.getBuf(), provider.getCurrentSize(), len);
            provider.incCurrentSize(len);
        }
        if (provider.getCurrentSize() == maxWriteSize) flush();
    }

    @Override
    public void flush() throws IOException {
        verifyConnectionNotClosed();

        while (provider.isAvailable()) {
            SMB2WriteRequest wreq = new SMB2WriteRequest(connection.getNegotiatedProtocol().getDialect(), fileId,
                session.getSessionId(), treeConnect.getTreeId(), provider, connection.getNegotiatedProtocol().getMaxWriteSize());
            Future<SMB2WriteResponse> writeFuture = connection.send(wreq);
            SMB2WriteResponse wresp = Futures.get(writeFuture, TransportException.Wrapper);
            if (wresp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(wresp.getHeader().getStatus(), "Write failed for " + this);
            }
            provider.resetCurrentSize();
            provider.resetReadPosition();
            if (progressListener != null)
                progressListener.onProgressChanged(wresp.getBytesWritten(), provider.getOffset());
        }
    }

    @Override
    public void close() throws IOException {
        flush();
        isClosed = true;
        provider.clean();
        treeConnect = null;
        session = null;
        connection = null;
        logger.debug("EOF, {} bytes written", provider.getOffset());
    }

    private void verifyConnectionNotClosed() throws IOException {
        if (isClosed) throw new IOException("Stream is closed");
    }

    private static class ByteArrayProvider extends ByteChunkProvider {

        private byte[] buf;
        private int maxWriteSize;
        private int currentSize;
        private int readPosition;

        private ByteArrayProvider(int maxWriteSize) {
            this.maxWriteSize = maxWriteSize;
        }

        @Override
        public boolean isAvailable() {
            return currentSize - readPosition > 0;
        }

        @Override
        protected int getChunk(byte[] chunk) throws IOException {
            int len = currentSize - readPosition < chunk.length ? currentSize - readPosition : chunk.length;
            System.arraycopy(buf, readPosition, chunk, 0, len);
            readPosition = readPosition + len;
            return len;
        }

        @Override
        public int bytesLeft() {
            return currentSize - readPosition;
        }

        private byte[] getBuf() {
            if (buf == null)
                buf = new byte[maxWriteSize];
            return buf;
        }

        private void clean() {
            buf = null;
        }

        private int getCurrentSize() {
            return currentSize;
        }

        private void incCurrentSize() {
            incCurrentSize(1);
        }

        private void incCurrentSize(int i) {
            currentSize += i;
        }

        private void resetCurrentSize() {
            currentSize = 0;
        }

        private void resetReadPosition() {
            readPosition = 0;
        }
    }
}
