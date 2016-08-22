/*uuuunew file
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
import com.hierynomus.smbj.common.SMBException;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;

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
    private BlockingQueue<WriteResponseWrapper> responses = new ArrayBlockingQueue<>(MAX_QUEUE_SIZE);
    private Thread writeHandler;
    private AtomicReference<String> writeExceptionMessage = new AtomicReference<>(EMPTY);
    private boolean isClosed = false;

    private static final String EMPTY = "";
    private static final int MAX_QUEUE_SIZE = 30;
    private static final Logger logger = LoggerFactory.getLogger(FileOutputStream.class);

    public FileOutputStream(SMB2FileId fileId, TreeConnect treeConnect, ProgressListener progressListener) {
        this.treeConnect = treeConnect;
        this.fileId = fileId;
        this.session = treeConnect.getSession();
        this.connection = session.getConnection();
        this.progressListener = progressListener;
        this.maxWriteSize = connection.getNegotiatedProtocol().getMaxWriteSize();
        this.buf = new byte[maxWriteSize];
        setUpWriteHandler();
    }

    @Override
    public void write(int b) throws IOException {
        validateState();

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
        validateState();
        if (curr < maxWriteSize) {
            System.arraycopy(b, off, buf, curr, len);
            curr = curr + len;
        }
        if (curr == maxWriteSize) flush();
    }

    @Override
    public void flush() throws IOException {
        validateState();
        SMB2WriteRequest wreq = new SMB2WriteRequest(connection.getNegotiatedProtocol().getDialect(), fileId,
            session.getSessionId(), treeConnect.getTreeId(),
            buf, curr, offset, 0);
        Future<SMB2WriteResponse> writeFuture = connection.send(wreq);
        put(new WriteResponseWrapper(writeFuture, Type.PROCESS));
        offset += curr;
        curr = 0;

        if (progressListener != null) progressListener.onProgressChanged(offset, -1);
    }

    @Override
    public void close() throws IOException {
        flush();
        isClosed = true;
        cleanUp();
        logger.debug("EOF, {} bytes written", offset);
    }

    private void cleanUp() throws IOException {
        sendTerminationMessageToWriteHandler();
        try {
            writeHandler.join();
        } catch (InterruptedException e) {
            throw new RuntimeException("Interrupted while waiting to join");
        }
        verifyNoExceptionThrown();
        buf = null;
        treeConnect = null;
        session = null;
        connection = null;
    }

    private void validateState() throws IOException {
        verifyConnectionNotClosed();
        verifyNoExceptionThrown();
    }

    private void verifyNoExceptionThrown() throws IOException {
        if (!writeExceptionMessage.get().isEmpty()) {
            responses.clear();
            isClosed = true;
            buf = null;
            treeConnect = null;
            session = null;
            connection = null;
            throw new SMBException(writeExceptionMessage.get());
        }
    }

    private void verifyConnectionNotClosed() throws IOException {
        if (isClosed) throw new IOException("Stream is closed");
    }

    private void setUpWriteHandler() {
        writeHandler = new Thread() {
            boolean isRunning = true;

            @Override
            public void run() {
                while (isRunning) {
                    try {
                        WriteResponseWrapper response = responses.take();
                        if (isTerminationMessage(response.getType())) {
                            isRunning = false;
                            return;
                        }
                        Future<SMB2WriteResponse> res = response.getResponse();
                        SMB2WriteResponse wresp = Futures.get(res, TransportException.Wrapper);
                        if (wresp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                            throw new SMBRuntimeException(String.format("Write failed with status %s for thread %s",
                                wresp.getHeader().getStatus(), this));
                        }
                    } catch (InterruptedException e) {
                        throw new SMBRuntimeException(e);
                    } catch (TransportException e) {
                        throw new SMBRuntimeException(e);
                    }
                }
            }
        };

        Thread.UncaughtExceptionHandler h = new Thread.UncaughtExceptionHandler() {
            public void uncaughtException(Thread th, Throwable ex) {
                writeExceptionMessage.compareAndSet(EMPTY, ex.getMessage());
            }
        };
        writeHandler.setUncaughtExceptionHandler(h);
        writeHandler.setDaemon(true);
        writeHandler.start();
    }

    private void sendTerminationMessageToWriteHandler() {
        put(new WriteResponseWrapper(null, Type.EXIT));
    }

    private void put(WriteResponseWrapper response) {
        try {
            responses.put(response);
        } catch (InterruptedException e) {
            throw new RuntimeException("Interrupted while adding WriteResponseWrapper");
        }
    }

    private boolean isTerminationMessage(Type type) {
        return type == Type.EXIT;
    }

    private class WriteResponseWrapper {

        private Future<SMB2WriteResponse> response;
        private Type type;

        private WriteResponseWrapper(Future<SMB2WriteResponse> response, Type type) {
            this.response = response;
            this.type = type;
        }

        private Future<SMB2WriteResponse> getResponse() {
            return response;
        }

        private Type getType() {
            return type;
        }
    }

    private enum Type {EXIT, PROCESS}
}
