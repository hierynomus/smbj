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
package com.hierynomus.smbj.transport.tcp.async;

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.protocol.transport.PacketFactory;
import com.hierynomus.protocol.transport.PacketReceiver;
import com.hierynomus.smbj.transport.PacketReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class AsyncPacketReader<P extends Packet<?>> {
    private static final Logger logger = LoggerFactory.getLogger(PacketReader.class);

    private final PacketFactory<P> packetFactory;
    private PacketReceiver<P> handler;
    private final AsynchronousSocketChannel channel;
    private String remoteHost;
    private int soTimeout = 0;

    private AtomicBoolean stopped = new AtomicBoolean(false);

    public AsyncPacketReader(AsynchronousSocketChannel channel, PacketFactory<P> packetFactory,
                             PacketReceiver<P> handler) {
        this.channel = channel;
        this.packetFactory = packetFactory;
        this.handler = handler;
    }

    public void start(String remoteHost, int soTimeout) {
        this.remoteHost = remoteHost;
        this.soTimeout = soTimeout;
        initiateNextRead(new PacketBufferReader());
    }

    public void stop() {
        stopped.set(true);
    }

    private void initiateNextRead(PacketBufferReader bufferReader) {
        if (stopped.get()) {
            logger.trace("Stopped, not initiating another read operation.");
            return;
        }
        logger.trace("Initiating next read");
        channel.read(bufferReader.getBuffer(), this.soTimeout, TimeUnit.MILLISECONDS, bufferReader,
            new CompletionHandler<Integer, PacketBufferReader>() {

                @Override
                public void completed(Integer bytesRead, PacketBufferReader reader) {
                    logger.trace("Received {} bytes", bytesRead);
                    if (bytesRead < 0) {
                        handleClosedReader();
                        return; // stop the read cycle
                    }
                    try {
                        processPackets(reader);
                        initiateNextRead(reader);
                    } catch (RuntimeException e) {
                        handleAsyncFailure(e);
                    }
                }

                @Override
                public void failed(Throwable exc, PacketBufferReader attachment) {
                    handleAsyncFailure(exc);
                }

                private void processPackets(PacketBufferReader reader) {
                    for (byte[] packetBytes = reader.readNext(); packetBytes != null; packetBytes = reader
                        .readNext()) {
                        readAndHandlePacket(packetBytes);
                    }
                }

                private void handleClosedReader() {
                    if (!stopped.get()) {
                        handleAsyncFailure(new EOFException("Connection closed by server"));
                    }
                }

            });
    }

    private void readAndHandlePacket(byte[] packetBytes) {
        try {
            P packet = packetFactory.read(packetBytes);
            logger.trace("Received packet << {} >>", packet);
            handler.handle(packet);
        } catch (BufferException | IOException e) {
            handleAsyncFailure(e);
        }
    }

    private void handleAsyncFailure(Throwable exc) {
        if (isChannelClosedByOtherParty(exc)) {
            logger.trace("Channel to {} closed by other party, closing it locally.", remoteHost);
        } else {
            String excClass = exc.getClass().getSimpleName();
            logger.trace("{} on channel to {}, closing channel: {}", excClass, remoteHost, exc.getMessage());
        }
        closeChannelQuietly();
    }

    private boolean isChannelClosedByOtherParty(Throwable exc) {
        return exc instanceof AsynchronousCloseException;
    }

    private void closeChannelQuietly() {
        try {
            channel.close();
        } catch (IOException e) {
            String eClass = e.getClass().getSimpleName();
            logger.debug("{} while closing channel to {} on failure: {}", eClass, remoteHost, e.getMessage());
        }
    }

}
