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
package com.hierynomus.smbj.transport.tcp;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.smbj.transport.PacketFactory;
import com.hierynomus.smbj.transport.PacketReader;
import com.hierynomus.smbj.transport.PacketReceiver;
import com.hierynomus.smbj.transport.TransportException;

public class AsyncPacketReader<P extends Packet<P, ?>> {
    private static final Logger logger = LoggerFactory.getLogger(PacketReader.class);

    private final PacketFactory<P> packetFactory;
    private PacketReceiver<P> handler;
    private final AsynchronousSocketChannel channel;
    private String remoteHost;
    private int soTimeout = 0;

    private AtomicBoolean stopped = new AtomicBoolean(false);

    private static final int READ_BUFFER_CAPACITY = 9000; // Size of a Jumbo frame
    private static final int HEADER_SIZE = 4;

    private final ByteBuffer readBuffer;
    private int bytesWaitingToBeProcessed = 0;

    private static final int NO_PACKET_LENGTH = -1;

    private int currentPacketLength = NO_PACKET_LENGTH;


    public AsyncPacketReader(AsynchronousSocketChannel channel, PacketFactory<P> packetFactory,
            PacketReceiver<P> handler) {
        this.channel = channel;
        this.packetFactory = packetFactory;
        this.handler = handler;
        this.readBuffer = ByteBuffer.allocate(READ_BUFFER_CAPACITY);
        this.readBuffer.order(ByteOrder.BIG_ENDIAN);
    }

    public void start(String remoteHost, int soTimeout) {
        this.remoteHost = remoteHost;
        this.soTimeout = soTimeout;
        initiateNextRead();
    }
    
    public void stop() {
        stopped.set(true);
    }

    private void initiateNextRead() {
        if (stopped.get()) {
            logger.debug("Stopped, not initiating another read operation.");
        }
        channel.read(readBuffer, this.soTimeout, TimeUnit.MILLISECONDS, null, new CompletionHandler<Integer, Object>() {
            @Override
            public void completed(Integer bytesRead, Object attachment) {
                try {
                    readPacket(bytesRead);
                } catch (TransportException e) {
                    handleAsyncFailure(e);
                }
            }

            @Override
            public void failed(Throwable exc, Object attachment) {
                handleAsyncFailure(exc);
            }

        });
    }

    private void readPacket(int bytesRead) throws TransportException {
        if (bytesRead < 0) {
            handleEndOfData();
            return; // don't try to read more data
        }
        if (isAwaitingHeader()) {
            readPacketHeaderAndBody(bytesRead);
        } else {
            readPacketBody(bytesRead);
        }
        initiateNextRead();
    }

    private void handleEndOfData() {
        if (!stopped.get()) {
            handleAsyncFailure(new EOFException("Connection closed by server"));
        }
    }

    private boolean isAwaitingHeader() {
        return currentPacketLength == NO_PACKET_LENGTH;
    }

    private void readPacketHeaderAndBody(int bytesRead) {
        if (!ensureBytesAvailable(bytesRead, HEADER_SIZE)) {
            return; // can't read header yet
        }
        this.currentPacketLength = readBuffer.getInt() & 0xffffff;
        readPacketBody(0);
    }

    private void readPacketBody(int bytesRead) {
        if (!ensureBytesAvailable(bytesRead, this.currentPacketLength)) {
            return; // can't read body yet
        }
        byte[] buf = new byte[this.currentPacketLength];
        readBuffer.get(buf);
        P packet;
        try {
            packet = packetFactory.read(buf);
            logger.debug("Received packet << {} >>", packet);
            handler.handle(packet);
        } catch (BufferException | TransportException e) {
            handleAsyncFailure(e);
        }
        resetPacketReadState();
    }

    private void resetPacketReadState() {
        this.bytesWaitingToBeProcessed = 0;
        this.currentPacketLength = NO_PACKET_LENGTH;
        this.readBuffer.compact();
        this.readBuffer.flip();
    }

    private boolean ensureBytesAvailable(int bytesRead, int bytesNeeded) {
        bytesWaitingToBeProcessed += bytesRead;
        return bytesWaitingToBeProcessed >= bytesNeeded;
    }

    private void handleAsyncFailure(Throwable exc) {
        String excClass = exc.getClass().getSimpleName();
        logger.info("{} on channel to {}, closing channel: {}", excClass, remoteHost, exc.getMessage());
        try {
            channel.close();
        } catch (IOException e) {
            String eClass = e.getClass().getSimpleName();
            logger.debug("{} while closing channel to {} on failure: {}", eClass, remoteHost, e.getMessage());
        }
    }

}
