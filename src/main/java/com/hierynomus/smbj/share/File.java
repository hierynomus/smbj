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
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2ReadRequest;
import com.hierynomus.mssmb2.messages.SMB2ReadResponse;
import com.hierynomus.mssmb2.messages.SMB2WriteRequest;
import com.hierynomus.mssmb2.messages.SMB2WriteResponse;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.Future;

public class File extends DiskEntry {

    private static final Logger logger = LoggerFactory.getLogger(File.class);

    public File(SMB2FileId fileId, TreeConnect treeConnect, String fileName) {
        super(treeConnect, fileId, fileName);
    }

    public void write(InputStream srcStream) throws IOException, SMBApiException {
        write(null);
    }
    public void write(InputStream srcStream, ProgressListener progressListener) throws IOException, SMBApiException {

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        byte[] buf = new byte[connection.getNegotiatedProtocol().getMaxWriteSize()];
        OutputStream os = getOutputStream(progressListener);
        int numRead = -1;
        while ((numRead = srcStream.read(buf)) != -1) {
            os.write(buf, 0, numRead);
            os.flush();
        }
        os.close();
    }

    public void read(OutputStream destStream) throws IOException,
        SMBApiException {
        read(destStream, null);
    }
    public void read(OutputStream destStream, ProgressListener progressListener) throws IOException,
            SMBApiException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();
        InputStream is = getInputStream(progressListener);
        int numRead = -1;
        byte[] buf = new byte[connection.getNegotiatedProtocol().getMaxWriteSize()];
        while ((numRead = is.read(buf)) != -1) {
            destStream.write(buf, 0, numRead);
        }
        is.close();
    }

    public InputStream getInputStream() {
        return getInputStream(null);
    }

    private InputStream getInputStream(final ProgressListener listener) {

        return new InputStream() {
            private Session session = treeConnect.getSession();
            private Connection connection = session.getConnection();
            private long offset = 0;
            private int curr = 0;
            private byte[] buf;
            private boolean isClosed = false;
            private ProgressListener progressListener = listener;

            @Override
            public int read() throws IOException {
                if (isClosed)
                    throw new IOException("Stream is closed");

                if (buf != null && curr < buf.length) {
                    ++curr;
                    return buf[curr - 1] & 0xFF;
                }

                SMB2ReadRequest rreq = new SMB2ReadRequest(connection.getNegotiatedProtocol(), getFileId(),
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

                if(rresp.getHeader().getStatus() == NtStatus.STATUS_END_OF_FILE) {
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
        };
    }

    public OutputStream getOutputStream() {
        return getOutputStream(null);
    }

    private OutputStream getOutputStream(final ProgressListener listener) {

        return new OutputStream() {
            private Session session = treeConnect.getSession();
            private Connection connection = session.getConnection();
            private int maxWriteSize = connection.getNegotiatedProtocol().getMaxWriteSize();
            private ProgressListener progressListener = listener;

            private byte[] buf = new byte[maxWriteSize];
            private long offset = 0;
            private int curr = 0;
            private boolean isClosed = false;

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
            public void flush() throws IOException {
                SMB2WriteRequest wreq = new SMB2WriteRequest(connection.getNegotiatedProtocol().getDialect(), getFileId(),
                    session.getSessionId(), treeConnect.getTreeId(),
                    buf, curr, offset, 0);
                Future<SMB2WriteResponse> writeFuture = connection.send(wreq);
                SMB2WriteResponse wresp = Futures.get(writeFuture, TransportException.Wrapper);

                if (wresp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                    throw new SMBApiException(wresp.getHeader().getStatus(), "Write failed for " + this);
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
                session = null;
                connection = null;
                buf = null;
            }
        };

    }

    @Override
    public String toString() {
        return "File{" +
                "fileId=" + fileId +
                ", fileName='" + fileName + '\'' +
                '}';
    }

}
