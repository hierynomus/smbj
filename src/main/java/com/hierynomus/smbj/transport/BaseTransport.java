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
package com.hierynomus.smbj.transport;

import com.hierynomus.mssmb2.SMB2Header;
import com.hierynomus.mssmb2.SMB2MessageFlag;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.smbj.common.SMBBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.locks.ReentrantLock;

public abstract class BaseTransport implements TransportLayer {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    protected InputStream in;
    protected OutputStream out;

    private final ReentrantLock writeLock = new ReentrantLock();

    @Override
    public void init(InputStream in, OutputStream out) {
        this.in = in;
        this.out = out;
    }

    @Override
    public void write(SMB2Packet packet) throws TransportException {
        writeLock.lock();
        try {
            try {
                SMBBuffer buffer = new SMBBuffer();
                packet.write(buffer);
                logger.trace("Writing packet << {} >>, sequence number << {} >>", packet.getHeader().getMessage(), packet.getSequenceNumber());
                doWrite(buffer);
                out.flush();
            } catch (IOException ioe) {
                throw new TransportException(ioe);
            }
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public void writeSigned(SMB2Packet packet, byte[] sessionKey) throws TransportException {
        writeLock.lock();
        try {
            try {
                packet.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SIGNED);
                SMBBuffer buffer = new SMBBuffer();
                packet.write(buffer);
                Mac sha256_HMAC = null;
                try {
                    sha256_HMAC = Mac.getInstance("HMACSHA256");

                    SecretKeySpec secret_key = new SecretKeySpec(sessionKey, "HMACSHA256");
                    sha256_HMAC.init(secret_key);
                    byte[] dataToSign = buffer.getCompactData();
                    byte[] signature = sha256_HMAC.doFinal(dataToSign);
                    System.arraycopy(signature, 0, buffer.array(), SMB2Header.SIGNATURE_OFFSET, 16);
                } catch (Exception e) {
                    throw new TransportException(e);
                }

                logger.trace("Writing packet << {} >>, sequence number << {} >>", packet.getHeader().getMessage(), packet.getSequenceNumber());
                doWrite(buffer);
                out.flush();
            } catch (IOException ioe) {
                throw new TransportException(ioe);
            }
        } finally {
            writeLock.unlock();
        }
    }

    protected abstract void doWrite(SMBBuffer packetData) throws IOException;
}
