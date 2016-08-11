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
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;

public class FileOutputStream extends OutputStream {

    private TreeConnect treeConnect;
    private SMB2FileId fileId;
    private Session session;
    private Connection connection;
    private int maxWriteSize;
    private ProgressListener progressListener;

    private byte[] buf;
    private long offset = 0;
    private int curr = 0;
    private boolean isClosed = false;
    private List<Future<SMB2WriteResponse>> responses = new ArrayList<>();
    private int availableCredits;
    private static final Logger logger = LoggerFactory.getLogger(FileOutputStream.class);

    public FileOutputStream(SMB2FileId fileId, TreeConnect treeConnect, ProgressListener progressListener) {
        this.treeConnect = treeConnect;
        this.fileId = fileId;
        this.session = treeConnect.getSession();
        this.connection = session.getConnection();
        this.progressListener = progressListener;
        this.maxWriteSize = connection.getNegotiatedProtocol().getMaxWriteSize();
        this.buf = new byte[maxWriteSize];
        this.availableCredits = connection.getConnectionInfo().getSequenceWindow().available();
    }

    @Override
    public void write(int b) throws IOException {
        if (isClosed) throw new IOException("Stream is closed");

        if (curr < maxWriteSize) {
            buf[curr] = (byte) b;
            ++curr;
        }
        if (curr == maxWriteSize) flush();
    }

    @Override
    public void write(byte b[]) throws IOException {
        write(b, 0, b.length);
    }

    @Override
    public void write(byte b[], int off, int len) throws IOException {
        if (isClosed) throw new IOException("Stream is closed");

        if (curr < maxWriteSize) {
            System.arraycopy(b, off, buf, curr, len);
            curr = curr + len;
        }
        if (curr == maxWriteSize) flush();
    }

    @Override
    public void flush() throws IOException {
        SMB2WriteRequest wreq = new SMB2WriteRequest(connection.getNegotiatedProtocol().getDialect(), fileId,
            session.getSessionId(), treeConnect.getTreeId(),
            buf, curr, offset, 0);
        Future<SMB2WriteResponse> writeFuture = connection.send(wreq);
        if (availableCredits > responses.size())
            responses.add(writeFuture);

        if (responses.size() == availableCredits) {
            processResponses();
        }
        offset += curr;
        curr = 0;

        if (progressListener != null) progressListener.onProgressChanged(offset, -1);
        if (isClosed) logger.debug("EOF, {} bytes written", offset);
    }

    @Override
    public void close() throws IOException {
        isClosed = true;
        flush();
        processResponses();
        session = null;
        connection = null;
        buf = null;
    }

    private void processResponses() throws TransportException {
        for (Future<SMB2WriteResponse> res : responses) {
            SMB2WriteResponse wresp = Futures.get(res, TransportException.Wrapper);

            if (wresp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(wresp.getHeader().getStatus(), "Write failed for " + this);
            }
        }
        responses.clear();
    }

}
