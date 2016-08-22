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
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class File extends DiskEntry {

    private static final Logger logger = LoggerFactory.getLogger(File.class);

    public File(SMB2FileId fileId, TreeConnect treeConnect, String fileName) {
        super(treeConnect, fileId, fileName);
    }

    public void write(InputStream srcStream) throws IOException, SMBApiException {
        write(srcStream, null);
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
        return new FileInputStream(fileId, treeConnect, listener);
    }

    public OutputStream getOutputStream() {
        return getOutputStream(null);
    }

    private OutputStream getOutputStream(final ProgressListener listener) {
        return new FileOutputStream(fileId, treeConnect, listener);
    }

    @Override
    public String toString() {
        return "File{" +
                "fileId=" + fileId +
                ", fileName='" + fileName + '\'' +
                '}';
    }

}
