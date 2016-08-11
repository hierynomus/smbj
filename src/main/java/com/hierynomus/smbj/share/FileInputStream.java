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
import com.hierynomus.mssmb2.messages.SMB2ReadRequest;
import com.hierynomus.mssmb2.messages.SMB2ReadResponse;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.Future;

public class FileInputStream extends InputStream {

    protected TreeConnect treeConnect;
    private Session session;
    private Connection connection;
    private SMB2FileId fileId;
    private long offset = 0;
    private int curr = 0;
    private byte[] buf;
    private boolean isClosed = false;
    private ProgressListener progressListener;
    private static final Logger logger = LoggerFactory.getLogger(FileInputStream.class);

    public FileInputStream(SMB2FileId fileId, TreeConnect treeConnect, ProgressListener progressListener) {
        this.treeConnect = treeConnect;
        this.fileId = fileId;
        this.session = treeConnect.getSession();
        this.connection = session.getConnection();
        this.progressListener = progressListener;
    }

    @Override
    public int read() throws IOException {
        if (isClosed)
            throw new IOException("Stream is closed");

        if (buf != null && curr < buf.length) {
            ++curr;
            return buf[curr - 1] & 0xFF;
        }

        SMB2ReadRequest rreq = new SMB2ReadRequest(connection.getNegotiatedProtocol(), fileId,
            session.getSessionId(), treeConnect.getTreeId(), offset);

        Future<SMB2ReadResponse> readResponseFuture = connection.send(rreq);
        SMB2ReadResponse rresp = Futures.get(readResponseFuture, TransportException.Wrapper);

        if (rresp.getHeader().getStatus() == NtStatus.STATUS_SUCCESS) {
            buf = rresp.getData();
            curr = 0;
            offset += rresp.getDataLength();
            if (progressListener != null) progressListener.onProgressChanged(offset, -1);
            if (buf != null && curr < buf.length) {
                ++curr;
                return buf[curr - 1] & 0xFF;
            }
        }

        if (rresp.getHeader().getStatus() == NtStatus.STATUS_END_OF_FILE) {
            logger.debug("EOF, {} bytes read", offset);
            return -1;
        }

        throw new SMBApiException(rresp.getHeader().getStatus(), "Read failed for " + this);
    }

    @Override
    public void close() throws IOException {
        isClosed = true;
        session = null;
        connection = null;
        buf = null;
    }

    @Override
    public int available() throws IOException {
        throw new IOException("Available not supported");
    }
}
