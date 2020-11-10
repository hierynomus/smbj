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
import com.hierynomus.protocol.PacketData;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.protocol.transport.PacketHandlers;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smbj.common.SMBRuntimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.CompletionHandler;
import java.util.Queue;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A transport layer over Direct TCP/IP that uses asynchronous I/O.
 */
public class AsyncDirectTcpTransport<D extends PacketData<?>, P extends Packet<?>> implements TransportLayer<P> {
    private static final int DEFAULT_CONNECT_TIMEOUT = 5000;
    private static final int DIRECT_HEADER_SIZE = 4;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final PacketHandlers<D, P> handlers;
    private final AsynchronousSocketChannel socketChannel;
    private final AsyncPacketReader<D> packetReader;
    private final AtomicBoolean connected;
    private int soTimeout = 0;

    // AsynchronousSocketChannel doesn't support concurrent writes, so queue pending writes for later
    private final Queue<ByteBuffer> writeQueue;
    private AtomicBoolean writingNow;

    public AsyncDirectTcpTransport(int soTimeout, PacketHandlers<D, P> handlers, AsynchronousChannelGroup group)
        throws IOException {
        this.soTimeout = soTimeout;
        this.handlers = handlers;
        this.socketChannel = AsynchronousSocketChannel.open(group);
        this.packetReader = new AsyncPacketReader<>(this.socketChannel, handlers.getPacketFactory(),
            handlers.getReceiver());
        this.writeQueue = new LinkedBlockingQueue<>();
        this.connected = new AtomicBoolean(false);
        this.writingNow = new AtomicBoolean(false);
    }

    @Override
    public void write(P packet) throws TransportException {
        ByteBuffer bufferToSend = prepareBufferToSend(packet); // Serialize first, as it might throw
        logger.trace("Sending packet << {} >>", packet);
        writeOrEnqueue(bufferToSend);
    }

    private void writeOrEnqueue(ByteBuffer buffer) {
        synchronized (this) {
            writeQueue.add(buffer);
            if (!writingNow.getAndSet(true)) {
                startAsyncWrite();
            }
        }
    }

    @Override
    public void connect(InetSocketAddress remoteAddress) throws IOException {
        String remoteHostname = remoteAddress.getHostString();
        try {
            Future<Void> connectFuture = socketChannel.connect(remoteAddress);
            connectFuture.get(DEFAULT_CONNECT_TIMEOUT, TimeUnit.MILLISECONDS);
            connected.set(true);
        } catch (ExecutionException | TimeoutException e) {
            throw TransportException.Wrapper.wrap(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw TransportException.Wrapper.wrap(e);
        }
        packetReader.start(remoteHostname, this.soTimeout);
    }

    @Override
    public void disconnect() throws IOException {
        // Mark disconnected first
        connected.set(false);
        socketChannel.close();
    }

    @Override
    public boolean isConnected() {
        return connected.get();
    }

    public void setSoTimeout(int soTimeout) {
        this.soTimeout = soTimeout;
    }

    private void startAsyncWrite() {
        if (!isConnected()) {
            throw new IllegalStateException("Transport is not connected");
        }
        ByteBuffer toSend = writeQueue.peek();
        socketChannel.write(toSend, soTimeout, TimeUnit.MILLISECONDS, null, new CompletionHandler<Integer, Object>() {

            @Override
            public void completed(Integer result, Object attachment) {
                logger.trace("Written {} bytes to async transport", result);
                startNextWriteIfWaiting();
            }

            @Override
            public void failed(Throwable exc, Object attachment) {
                try {
                    if (exc instanceof ClosedChannelException) {
                        connected.set(false);
                    } else {
                        startNextWriteIfWaiting();
                    }
                } finally {
                    handlers.getReceiver().handleError(exc);
                }
            }

            private void startNextWriteIfWaiting() {
                synchronized (AsyncDirectTcpTransport.this) {
                    ByteBuffer head = writeQueue.peek();
                    if (head != null && head.hasRemaining()) {
                        startAsyncWrite();
                    } else if (head != null) {
                        writeQueue.remove();
                        startNextWriteIfWaiting();
                    } else {
                        writingNow.set(false);
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
