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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.hierynomus.mssmb2.SMB2MessageFlag;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.smbj.common.MessageSigning;
import com.hierynomus.smbj.common.SMBBuffer;

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
    public void writeSigned(SMB2Packet packet, SecretKeySpec signingKeySpec) throws TransportException {
        writeLock.lock();
        try {
            try {
                SMBBuffer buffer = new SMBBuffer();
                packet.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SIGNED); // set the SMB2_FLAGS_SIGNED flag
                packet.write(buffer);

                signBuffer(buffer, signingKeySpec);

                logger.trace("Writing packet << {} >>, sequence number << {} >>", packet.getHeader().getMessage(), packet.getSequenceNumber());
                doWrite(buffer);
                out.flush();
            } catch (IOException | InvalidKeyException | NoSuchAlgorithmException ioe) {
                throw new TransportException(ioe);
            }
        } finally {
            writeLock.unlock();
        }
    }

    protected abstract void doWrite(SMBBuffer packetData) throws IOException;


    private static void signBuffer(SMBBuffer buffer, SecretKeySpec signingKeySpec) throws InvalidKeyException, NoSuchAlgorithmException {
        MessageSigning.signBuffer(buffer.array(), buffer.available(), signingKeySpec);
    }
}
