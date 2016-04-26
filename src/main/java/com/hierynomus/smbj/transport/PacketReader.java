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

import com.hierynomus.protocol.commons.concurrent.Promise;
import com.hierynomus.smbj.connection.SequenceWindow;
import com.hierynomus.smbj.smb2.SMB2Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

public abstract class PacketReader implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(PacketReader.class);

    protected InputStream in;
    private SequenceWindow sequenceWindow;
    private ConcurrentHashMap<Long, Promise<SMB2Packet, ?>> promises = new ConcurrentHashMap<>();

    public PacketReader(InputStream in, SequenceWindow sequenceWindow) {
        this.in = in;
        this.sequenceWindow = sequenceWindow;
    }

    @Override
    public void run() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                readPacket();
            } catch (TransportException e) {
                for (Promise<SMB2Packet, ?> smb2PacketPromise : promises.values()) {
                    smb2PacketPromise.deliverError(e);
                }
                throw new RuntimeException(e);
            }
        }
    }

    public void expectResponse(long messageId, Promise<SMB2Packet, ?> promise) {
        promises.put(messageId, promise);
    }

    private void readPacket() throws TransportException {
        SMB2Packet smb2Packet = doRead();
        logger.debug("Received packet << {} >>", smb2Packet);
        // Grant the credits from the response.
        sequenceWindow.creditsGranted(smb2Packet.getHeader().getCreditResponse());
        Promise<SMB2Packet, ?> smb2PacketPromise = promises.remove(smb2Packet.getSequenceNumber());
        if (smb2PacketPromise == null) {
            throw new TransportException(String.format("Unexpected packet with sequence number << %s >> received", smb2Packet.getSequenceNumber()));
        }
        smb2PacketPromise.deliver(smb2Packet);
    }

    /**
     * Read the actual SMB2 Packet from the {@link InputStream}
     * @return the read SMB2Packet
     * @throws TransportException
     */
    protected abstract SMB2Packet doRead() throws TransportException;
}
