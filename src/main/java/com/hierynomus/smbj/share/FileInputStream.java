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
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.mssmb2.messages.SMB2ReadResponse;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.protocol.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

class FileInputStream extends InputStream {

    private final long readTimeout;
    private File file;
    private long offset = 0;
    private int curr = 0;
    private byte[] buf;
    private ProgressListener progressListener;
    private boolean isClosed;
    private Future<SMB2ReadResponse> nextResponse;

    private static final Logger logger = LoggerFactory.getLogger(FileInputStream.class);
    private int bufferSize;

    FileInputStream(File file, int bufferSize, long readTimeout, ProgressListener progressListener) {
        this.file = file;
        this.bufferSize = bufferSize;
        this.progressListener = progressListener;
        this.readTimeout = readTimeout;
    }

    @Override
    public int read() throws IOException {
        if (buf == null || curr >= buf.length) {
            loadBuffer();
        }
        if (isClosed) {
            return -1;
        }
        return buf[curr++] & 0xFF;
    }

    @Override
    public int read(byte b[]) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte b[], int off, int len) throws IOException {
        if (buf == null || curr >= buf.length) {
            loadBuffer();
        }

        if (isClosed) {
            return -1;
        }

        int l = buf.length - curr > len ? len : buf.length - curr;
        System.arraycopy(buf, curr, b, off, l);
        curr += l;
        return l;
    }

    @Override
    public void close() throws IOException {
        isClosed = true;
        file = null;
        buf = null;
    }

    @Override
    public int available() throws IOException {
        return 0;
    }

    @Override
    public long skip(long n) throws IOException {
        if (buf == null) {
            offset += n;
        } else if (curr + n < buf.length) {
            curr += n;
        } else {
            offset += (curr + n) - buf.length;
            buf = null;
            nextResponse = null;
        }
        return n;
    }

    private void loadBuffer() throws IOException {

        if (nextResponse == null) {
            nextResponse = sendRequest();
        }

        SMB2ReadResponse res = Futures.get(nextResponse, readTimeout, TimeUnit.MILLISECONDS, TransportException.Wrapper);
        if (res.getHeader().getStatus() == NtStatus.STATUS_SUCCESS) {
            buf = res.getData();
            curr = 0;
            offset += res.getDataLength();
            if (progressListener != null) {
                progressListener.onProgressChanged(offset, -1);
            }
        }

        if (res.getHeader().getStatus() == NtStatus.STATUS_END_OF_FILE) {
            logger.debug("EOF, {} bytes read", offset);
            isClosed = true;
            return;
        }

        if (res.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(res.getHeader(), "Read failed for " + this);
        }

        nextResponse = sendRequest();
    }

    private Future<SMB2ReadResponse> sendRequest() throws IOException {
        return file.readAsync(offset, bufferSize);
    }
}
