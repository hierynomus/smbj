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
import java.util.concurrent.locks.ReentrantLock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.hierynomus.mssmb2.SMB2Packet;
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
        logger.trace("Acquiring write lock to send packet << {} >>", packet.getHeader().getMessage());
        writeLock.lock();
        try {
            try {
                SMBBuffer buffer = new SMBBuffer();
                packet.write(buffer);
                logger.debug("Writing packet << {} >>, sequence number << {} >>", packet.getHeader().getMessage(), packet.getSequenceNumber());
                doWrite(buffer);
                out.flush();
            } catch (IOException ioe) {
                throw new TransportException(ioe);
            }
        } finally {
            writeLock.unlock();
            logger.trace("Packet << {} >> sent, lock released.", packet.getHeader().getMessage());
        }
    }

    protected abstract void doWrite(SMBBuffer packetData) throws IOException;
}
