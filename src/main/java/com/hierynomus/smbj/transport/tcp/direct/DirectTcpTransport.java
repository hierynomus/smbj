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
package com.hierynomus.smbj.transport.tcp.direct;

import static java.lang.String.format;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.net.SocketFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.PacketData;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.socket.ProxySocketFactory;
import com.hierynomus.protocol.transport.PacketHandlers;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smbj.transport.PacketReader;

/**
 * A transport layer over Direct TCP/IP.
 */
public class DirectTcpTransport<D extends PacketData<?>, P extends Packet<?>> implements TransportLayer<P> {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final PacketHandlers<D, P> handlers;

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private SocketFactory socketFactory = new ProxySocketFactory();
    private int soTimeout;

    private volatile Socket socket;
    private BufferedOutputStream output;
    private PacketReader<D> packetReaderThread;
    private long disconnectCount;

    private static final int INITIAL_BUFFER_SIZE = 9000;

    public DirectTcpTransport(SocketFactory socketFactory, int soTimeout, PacketHandlers<D, P> handlers) {
        this.soTimeout = soTimeout;
        this.socketFactory = socketFactory;
        this.handlers = handlers;
    }

    @Override
    public void write(P packet) throws TransportException {
        logger.trace("Acquiring write lock to send packet << {} >>", packet);
        // Check again after acquiring the write lock to prevent a disconnect race.
        if (!isConnected()) {
            throw new TransportException(format("Cannot write %s as transport is disconnected", packet));
        }

        lock.writeLock().lock();
        try {
            if (!isConnected()) {
                throw new TransportException(format("Cannot write %s as transport got disconnected", packet));
            }

            logger.debug("Writing packet {}", packet);
            Buffer<?> packetData = handlers.getSerializer().write(packet);
            writeDirectTcpPacketHeader(packetData.available());
            writePacketData(packetData);
            output.flush();
            if (!isConnected()) {
                throw new TransportException(format("Cannot write %s as transport got disconnected", packet));
            }
            logger.trace("Packet {} sent, lock released.", packet);
        } catch (IOException ioe) {
            throw new TransportException(ioe);
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void connect(InetSocketAddress remoteAddress) throws IOException {
        long disconnects;
        synchronized (this) {
            disconnects = disconnectCount;
        }
        String remoteHostname = remoteAddress.getHostString();
        Socket newSocket = socketFactory.createSocket(remoteHostname, remoteAddress.getPort());
        synchronized (this) {
            if (disconnects == disconnectCount) {
                this.socket = newSocket;
                initWithSocket(remoteHostname);
                return;
            }
        }
        // A disconnect must also cancel a socket that is still being created.
        newSocket.close();
        throw new TransportException("Transport disconnected while connecting");
    }

    private void initWithSocket(String remoteHostname) throws IOException {
        this.socket.setSoTimeout(soTimeout);
        this.output = new BufferedOutputStream(this.socket.getOutputStream(), INITIAL_BUFFER_SIZE);
        packetReaderThread = new DirectTcpPacketReader<>(remoteHostname, socket.getInputStream(), handlers.getPacketFactory(), handlers.getReceiver());
        packetReaderThread.start();
    }


    @Override
    public void disconnect() throws IOException {
        Socket socketToClose;
        synchronized (this) {
            disconnectCount++;
            socketToClose = socket;
            if (socketToClose == null) {
                return;
            }
            socket = null;
            if (packetReaderThread != null) {
                packetReaderThread.stop();
            }
        }
        // Closing the socket must not wait for a writer stalled in flush(). Do not
        // close the buffered output stream: that would try to flush it again.
        if (!socketToClose.isClosed()) {
            socketToClose.close();
        }
    }

    @Override
    public boolean isConnected() {
        Socket currentSocket = socket;
        return currentSocket != null && currentSocket.isConnected() && !currentSocket.isClosed();
    }

    public void setSocketFactory(SocketFactory socketFactory) {
        this.socketFactory = socketFactory;
    }

    public void setSoTimeout(int soTimeout) {
        this.soTimeout = soTimeout;
    }

    private void writePacketData(Buffer<?> packetData) throws IOException {
        output.write(packetData.array(), packetData.rpos(), packetData.available());
    }

    private void writeDirectTcpPacketHeader(int size) throws IOException {
        output.write(0);
        output.write((byte) (size >> 16));
        output.write((byte) (size >> 8));
        output.write((byte) (size & 0xFF));
    }

}
