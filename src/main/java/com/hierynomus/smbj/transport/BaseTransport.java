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

import com.hierynomus.mssmb2.SMB2MessageFlag;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.smbj.common.MessageSigning;
import com.hierynomus.smbj.common.SMBBuffer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
    public void writeSigned(SMB2Packet packet, byte[] signingKey) throws TransportException {
        writeLock.lock();
        try {
            try {
                SMBBuffer buffer = new SMBBuffer();
                packet.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SIGNED); // set the SMB2_FLAGS_SIGNED flag
                packet.write(buffer);
                
                signBuffer(buffer, signingKey);
                
                logger.trace("Writing packet << {} >>, sequence number << {} >>", packet.getHeader().getMessage(), packet.getSequenceNumber());
                doWrite(buffer);
                out.flush();
            } catch (IOException ioe) {
                throw new TransportException(ioe);
            } catch (InvalidKeyException e) {
                throw new TransportException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new TransportException(e);
            }
        } finally {
            writeLock.unlock();
        }
    }

    protected abstract void doWrite(SMBBuffer packetData) throws IOException;

    
    // [MS-SMB2] 3.1.4.1 Signing An Outgoing Message
    // If Connection.Dialect is "2.0.2" or "2.1", the sender MUST compute a 32-byte hash using HMAC-SHA256 over the entire message, 
    // beginning with the SMB2 Header from step 1, and using the key provided.
    public static void signBuffer(SMBBuffer buffer, byte[] signingKey) throws InvalidKeyException, NoSuchAlgorithmException {
        MessageSigning.signBuffer(buffer.array(), buffer.available(), signingKey);
    }
}
