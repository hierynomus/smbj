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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.smbj.lock.CrossThreadLock;
import com.hierynomus.smbj.transport.PacketHandlers;
import com.hierynomus.smbj.transport.TransportException;
import com.hierynomus.smbj.transport.TransportLayer;

/**
 * A transport layer over Direct TCP/IP that uses asynchronous I/O.
 */
public class AsyncDirectTcpTransport<P extends Packet<P, ?>> implements TransportLayer<P> {
    public static final int DEFAULT_CONNECT_TIMEOUT = 5000;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final PacketHandlers<P> handlers;
    private final AsynchronousSocketChannel socketChannel;
    private final AsyncPacketReader<P> packetReader;
    private int soTimeout = 0;

    private final CrossThreadLock writeLock = new CrossThreadLock();

    public AsyncDirectTcpTransport(int soTimeout, PacketHandlers<P> handlers, AsynchronousChannelGroup group) throws IOException {
        this.soTimeout = soTimeout;
        this.handlers = handlers;
        this.socketChannel = AsynchronousSocketChannel.open(group);
        this.packetReader = new AsyncPacketReader<>(this.socketChannel, handlers.getPacketFactory(), handlers.getReceiver());
    }

    @Override
    public void write(P packet) throws TransportException {
        logger.trace("Acquiring write lock to send packet << {} >>", packet);
        writeLock.lock();
        try {
            try {
                logger.debug("Writing packet {}", packet);
                Buffer<?> packetData = handlers.getSerializer().write(packet);
                writePacket(packetData);
            } catch (IOException ioe) {
                throw new TransportException(ioe);
            }
        } finally {
            logger.trace("Packet {} sent, lock released.", packet);
        }
    }

    @Override
    public void connect(InetSocketAddress remoteAddress, InetSocketAddress localAddress) throws IOException {
        socketChannel.bind(localAddress);
        connect(remoteAddress);
    }

    @Override
    public void connect(InetSocketAddress remoteAddress) throws IOException {
        String remoteHostname = remoteAddress.getHostString();
        Future<Void> connectFuture = socketChannel.connect(remoteAddress);
        try {
            connectFuture.get(DEFAULT_CONNECT_TIMEOUT, TimeUnit.MILLISECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            throw new IOException(e);
        }
        packetReader.start(remoteHostname, this.soTimeout);
    }

    @Override
    public void disconnect() throws IOException {
        socketChannel.close();
    }

    @Override
    public boolean isConnected() {
        return socketChannel.isOpen();
    }

    public void setSoTimeout(int soTimeout) {
        this.soTimeout = soTimeout;
    }

    private void writePacket(Buffer<?> packetData) throws IOException {
        ByteBuffer toSend = prepareBufferToSend(packetData);
        socketChannel.write(toSend, soTimeout, TimeUnit.MILLISECONDS, null, new CompletionHandler<Integer, Object>() {

            @Override
            public void completed(Integer result, Object attachment) {
                writeLock.unlock();
            }

            @Override
            public void failed(Throwable exc, Object attachment) {
                writeLock.unlock();
                handlers.getReceiver().handleError(exc);
            }

        });
    }

    private ByteBuffer prepareBufferToSend(Buffer<?> packetData) {
        int dataSize = packetData.available();
        ByteBuffer toSend = ByteBuffer.allocate(dataSize + Integer.BYTES);
        toSend.order(ByteOrder.BIG_ENDIAN);
        toSend.putInt(packetData.available());
        toSend.put(packetData.array(), packetData.rpos(), packetData.available());
        toSend.flip();
        try {
            packetData.skip(dataSize);
        } catch (BufferException e) {
            throw new RuntimeException(e); // should never happen
        }
        return toSend;
    }

}
