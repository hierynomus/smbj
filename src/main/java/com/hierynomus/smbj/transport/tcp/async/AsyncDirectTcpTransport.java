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
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.protocol.transport.PacketHandlers;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.Queue;
import java.util.concurrent.*;

/**
 * A transport layer over Direct TCP/IP that uses asynchronous I/O.
 */
public class AsyncDirectTcpTransport<P extends Packet<?>> implements TransportLayer<P> {
    public static final int DEFAULT_CONNECT_TIMEOUT = 5000;
    private static final int DIRECT_HEADER_SIZE = 4;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final PacketHandlers<P> handlers;
    private final AsynchronousSocketChannel socketChannel;
    private final AsyncPacketReader<P> packetReader;
    private int soTimeout = 0;

    // AsynchronousSocketChannel doesn't support concurrent writes, so queue pending writes for later
    private final Queue<ByteBuffer> writeQueue;
    private boolean writingNow = false;

    public AsyncDirectTcpTransport(int soTimeout, PacketHandlers<P> handlers, AsynchronousChannelGroup group)
            throws IOException {
        this.soTimeout = soTimeout;
        this.handlers = handlers;
        this.socketChannel = AsynchronousSocketChannel.open(group);
        this.packetReader = new AsyncPacketReader<>(this.socketChannel, handlers.getPacketFactory(),
                handlers.getReceiver());
        this.writeQueue = new LinkedBlockingQueue<>();
    }

    @Override
    public void write(P packet) throws TransportException {
        ByteBuffer bufferToSend = prepareBufferToSend(packet); // Serialize first, as it might throw
        logger.trace("Sending packet << {} >>", packet);
        try {
            writeOrEnqueue(bufferToSend);
        } catch (IOException ioe) {
            throw TransportException.Wrapper.wrap(ioe);
        }
    }

    private void writeOrEnqueue(ByteBuffer buffer) throws IOException {
        synchronized (this) {
            if (!writingNow) {
                writingNow = true;
                startAsyncWrite(buffer);
            } else {
                writeQueue.add(buffer);
            }
        }
    }

    @Override
    public void connect(InetSocketAddress remoteAddress) throws IOException {
        String remoteHostname = remoteAddress.getHostString();
        Future<Void> connectFuture = socketChannel.connect(remoteAddress);
        try {
            connectFuture.get(DEFAULT_CONNECT_TIMEOUT, TimeUnit.MILLISECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            throw TransportException.Wrapper.wrap(e);
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

    private void startAsyncWrite(ByteBuffer toSend) {
        socketChannel.write(toSend, soTimeout, TimeUnit.MILLISECONDS, null, new CompletionHandler<Integer, Object>() {

            @Override
            public void completed(Integer result, Object attachment) {
                startNextWriteIfWaiting();
            }

            @Override
            public void failed(Throwable exc, Object attachment) {
                startNextWriteIfWaiting();
                handlers.getReceiver().handleError(exc);
            }

            private void startNextWriteIfWaiting() {
                synchronized (AsyncDirectTcpTransport.this) {
                    ByteBuffer nextBufferToWrite = writeQueue.poll();
                    if (nextBufferToWrite != null) {
                        startAsyncWrite(nextBufferToWrite);
                    } else {
                        writingNow = false;
                    }
                }
            }
        });
    }

    private ByteBuffer prepareBufferToSend(P packet) {
        Buffer<?> packetData = handlers.getSerializer().write(packet);
        int dataSize = packetData.available();
        ByteBuffer toSend = ByteBuffer.allocate(dataSize + DIRECT_HEADER_SIZE);
        toSend.order(ByteOrder.BIG_ENDIAN);
        toSend.putInt(packetData.available()); // also writes the initial 0 byte
        toSend.put(packetData.array(), packetData.rpos(), packetData.available());
        toSend.flip();
        try {
            packetData.skip(dataSize);
        } catch (BufferException e) {
            throw SMBRuntimeException.Wrapper.wrap(e); // should never happen
        }
        return toSend;
    }

}
