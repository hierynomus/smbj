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

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.socket.ProxySocketFactory;
import com.hierynomus.protocol.transport.PacketHandlers;
import com.hierynomus.smbj.transport.PacketReader;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.SocketFactory;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A transport layer over Direct TCP/IP.
 */
public class DirectTcpTransport<P extends Packet<?>> implements TransportLayer<P> {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final PacketHandlers<P> handlers;

    private final ReentrantLock writeLock = new ReentrantLock();

    private SocketFactory socketFactory = new ProxySocketFactory();
    private int soTimeout;

    private Socket socket;
    private BufferedOutputStream output;
    private PacketReader<P> packetReaderThread;

    private static final int INITIAL_BUFFER_SIZE = 9000;

    public DirectTcpTransport(SocketFactory socketFactory, int soTimeout, PacketHandlers<P> handlers) {
        this.soTimeout = soTimeout;
        this.socketFactory = socketFactory;
        this.handlers = handlers;
    }

    @Override
    public void write(P packet) throws TransportException {
        logger.trace("Acquiring write lock to send packet << {} >>", packet);
        writeLock.lock();
        try {
            try {
                logger.debug("Writing packet {}", packet);
                Buffer<?> packetData = handlers.getSerializer().write(packet);
                writeDirectTcpPacketHeader(packetData.available());
                writePacketData(packetData);
                output.flush();
            } catch (IOException ioe) {
                throw new TransportException(ioe);
            }
        } finally {
            writeLock.unlock();
            logger.trace("Packet {} sent, lock released.", packet);
        }
    }

    @Override
    public void connect(InetSocketAddress remoteAddress) throws IOException {
        String remoteHostname = remoteAddress.getHostString();
        this.socket = socketFactory.createSocket(remoteHostname, remoteAddress.getPort());
        initWithSocket(remoteHostname);
    }

    private void initWithSocket(String remoteHostname) throws IOException {
        this.socket.setSoTimeout(soTimeout);
        this.output = new BufferedOutputStream(this.socket.getOutputStream(), INITIAL_BUFFER_SIZE);
        packetReaderThread = new DirectTcpPacketReader<>(remoteHostname, socket.getInputStream(), handlers.getPacketFactory(), handlers.getReceiver());
        packetReaderThread.start();
    }


    @Override
    public void disconnect() throws IOException {
        if (!isConnected()) {
            return;
        }

        packetReaderThread.stop();
        if (socket.getInputStream() != null) {
            socket.getInputStream().close();
        }
        if (output != null) {
            output.close();
            output = null;
        }
        if (socket != null) {
            socket.close();
            socket = null;
        }
    }

    @Override
    public boolean isConnected() {
        return (socket != null) && socket.isConnected() && !socket.isClosed();
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
