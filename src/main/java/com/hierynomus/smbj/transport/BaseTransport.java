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

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.locks.ReentrantLock;

public abstract class BaseTransport<P extends Packet<P, ?>> implements TransportLayer<P> {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    protected InputStream in;
    protected OutputStream out;
    private PacketSerializer<P> serializer;
    private final ReentrantLock writeLock = new ReentrantLock();

    @Override
    public void init(InputStream in, OutputStream out, PacketSerializer<P> serializer) {
        this.in = in;
        this.out = out;
        this.serializer = serializer;
    }

    @Override
    public void write(P packet) throws TransportException {
        logger.trace("Acquiring write lock to send packet << {} >>", packet);
        writeLock.lock();
        try {
            try {
                logger.debug("Writing packet {}", packet);
                doWrite(serializer.write(packet));
                out.flush();
            } catch (IOException ioe) {
                throw new TransportException(ioe);
            }
        } finally {
            writeLock.unlock();
            logger.trace("Packet {} sent, lock released.", packet);
        }
    }

    protected abstract void doWrite(Buffer packetData) throws IOException;
}
