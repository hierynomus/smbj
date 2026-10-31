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
package com.hierynomus.smbj.connection;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2MessageFlag;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketFactory;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.PacketFactory;
import com.hierynomus.protocol.transport.PacketHandlers;
import com.hierynomus.protocol.transport.PacketReceiver;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smb.SMBPacketData;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.event.ConnectionClosed;
import com.hierynomus.smbj.event.SMBEvent;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.testing.PacketProcessor.NoOpPacketProcessor;
import com.hierynomus.smbj.testing.Utils;
import com.hierynomus.smbj.transport.PacketReader;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;

import javax.net.SocketFactory;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A negotiated stub connection followed by a real direct transport over controllable socket streams. */
public final class AbortTestConnection implements Closeable {
    public final Connection connection;
    public final TestSocket socket = new TestSocket();
    public final AtomicInteger errors = new AtomicInteger();
    public final AtomicInteger closedEvents;
    public final AtomicInteger packetsHandled = new AtomicInteger();
    public final Thread reader;
    public volatile RuntimeException receiverFailure;
    public volatile Error decoderFailure;

    public AbortTestConnection() throws Exception {
        this(new ClientContext());
    }

    public AbortTestConnection(ClientContext context) throws Exception {
        this(context, "127.0.0.1");
    }

    public AbortTestConnection(ClientContext context, String hostname) throws Exception {
        closedEvents = context.closedEvents.computeIfAbsent(hostname, key -> new AtomicInteger());
        connection = context.client.connect(hostname);
        connection.transport.disconnect();

        PacketReceiver<SMBPacketData<?>> receiver = new PacketReceiver<SMBPacketData<?>>() {
            @Override
            public void handle(SMBPacketData<?> packet) throws TransportException {
                if (receiverFailure != null) {
                    throw receiverFailure;
                }
                connection.handle(packet);
                packetsHandled.incrementAndGet();
            }

            @Override
            public void handleError(Throwable t) {
                errors.incrementAndGet();
                connection.handleError(t);
            }
        };
        PacketFactory<SMBPacketData<?>> factory = new PacketFactory<SMBPacketData<?>>() {
            private final SMB2PacketFactory delegate = new SMB2PacketFactory();

            @Override
            public SMBPacketData<?> read(byte[] data) throws Buffer.BufferException {
                if (decoderFailure != null) {
                    throw decoderFailure;
                }
                return delegate.read(data);
            }

            @Override
            public boolean canHandle(byte[] data) {
                return delegate.canHandle(data);
            }
        };
        DirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>> transport = new DirectTcpTransport<>(
            new TestSocketFactory(socket), 0, new PacketHandlers<>(new SMBPacketSerializer(), receiver, factory));
        connection.transport = transport;
        transport.connect(new InetSocketAddress(hostname, 445));
        Field readerField = DirectTcpTransport.class.getDeclaredField("packetReaderThread");
        readerField.setAccessible(true);
        Field threadField = PacketReader.class.getDeclaredField("thread");
        threadField.setAccessible(true);
        reader = (Thread) threadField.get(readerField.get(transport));
    }

    public static SMB2Echo echo() {
        return new SMB2Echo(SMB2Dialect.SMB_2_1);
    }

    public void respond(SMB2Packet request) {
        SMB2Echo response = echo();
        response.getHeader().setMessageId(request.getHeader().getMessageId());
        response.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR);
        socket.input.offer(frame(response));
    }

    public static byte[] frame(SMB2Packet packet) {
        Buffer<?> data = new SMBPacketSerializer().write(packet);
        int length = data.available();
        byte[] frame = new byte[length + 4];
        frame[1] = (byte) (length >> 16);
        frame[2] = (byte) (length >> 8);
        frame[3] = (byte) length;
        System.arraycopy(data.array(), data.rpos(), frame, 4, length);
        // The production header writer writes request status/credit fields.
        long status = packet.getHeader().getStatusCode();
        for (int i = 0; i < 4; i++) {
            frame[12 + i] = (byte) (status >> (8 * i));
        }
        return frame;
    }

    public void assertNoOutstandingRequests() throws Exception {
        for (String name : new String[] {"lookup", "cancelLookup"}) {
            Field field = OutstandingRequests.class.getDeclaredField(name);
            field.setAccessible(true);
            assertTrue(((Map<?, ?>) field.get(connection.outstandingRequests)).isEmpty(), name);
        }
    }

    public void awaitResponseWaiter(SMB2Packet packet) throws InterruptedException {
        Request request = connection.outstandingRequests.getRequestByMessageId(packet.getHeader().getMessageId());
        assertNotNull(request);
        await(() -> request.getPromise().hasWaiters());
    }

    @Override
    public void close() throws IOException {
        try {
            task(() -> {
                connection.close(true);
                return null;
            }).get(1, TimeUnit.SECONDS);
            reader.join(1000);
            assertFalse(reader.isAlive(), "packet reader did not stop");
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    public static <T> FutureTask<T> task(Callable<T> action) {
        FutureTask<T> task = new FutureTask<>(action);
        Thread thread = new Thread(task, "abort-test-worker");
        thread.setDaemon(true);
        thread.start();
        return task;
    }

    public static void await(BooleanSupplier condition) throws InterruptedException {
        long start = System.nanoTime();
        while (!condition.getAsBoolean() && System.nanoTime() - start < TimeUnit.SECONDS.toNanos(3)) {
            Thread.sleep(1);
        }
        assertTrue(condition.getAsBoolean(), "condition did not become true within three seconds");
    }

    public static void assertPrompt(long start) {
        assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(1), "abort took one second or longer");
    }

    public static Throwable transportFailure(Future<?> response) {
        ExecutionException failure = assertThrows(ExecutionException.class, () -> response.get(1, TimeUnit.SECONDS));
        Throwable cause = failure.getCause();
        while (!(cause instanceof TransportException) && cause.getCause() != null) {
            cause = cause.getCause();
        }
        assertTrue(cause instanceof TransportException, "Expected TransportException, got " + failure);
        assertTrue(response.isDone(), "failed response future must be done");
        return cause;
    }

    public static final class ClientContext implements Closeable {
        private final Map<String, AtomicInteger> closedEvents = new ConcurrentHashMap<>();
        private final SMBEventBus bus = new SMBEventBus() {
            @Override
            public void publish(SMBEvent event) {
                if (event instanceof ConnectionClosed) {
                    ConnectionClosed closed = (ConnectionClosed) event;
                    closedEvents.computeIfAbsent(closed.getHostname(), key -> new AtomicInteger()).incrementAndGet();
                }
                super.publish(event);
            }
        };
        public final SMBClient client = new SMBClient(Utils.config(new NoOpPacketProcessor()), bus);

        @Override
        public void close() {
            client.close();
        }
    }

    public static final class TestSocket extends Socket {
        public final BlockingInput input = new BlockingInput();
        public final BlockingOutput output = new BlockingOutput();
        public final AtomicInteger closeCalls = new AtomicInteger();
        private volatile boolean closed;

        @Override
        public boolean isConnected() {
            return true;
        }

        @Override
        public boolean isClosed() {
            return closed;
        }

        @Override
        public InputStream getInputStream() {
            return input;
        }

        @Override
        public OutputStream getOutputStream() {
            return output;
        }

        @Override
        public void setSoTimeout(int timeout) {
        }

        @Override
        public void close() {
            closeCalls.incrementAndGet();
            closed = true;
            input.close();
            output.close();
        }
    }

    public static final class BlockingInput extends InputStream {
        private final Deque<Byte> bytes = new ArrayDeque<>();
        private boolean closed;
        public volatile int consumed;
        public volatile boolean blocked;

        public synchronized void offer(byte[] data) {
            for (byte b : data) {
                bytes.add(b);
            }
            notifyAll();
        }

        @Override
        public synchronized int read(byte[] b, int off, int len) throws IOException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (bytes.isEmpty() && !closed) {
                blocked = true;
                try {
                    long remaining = deadline - System.nanoTime();
                    if (remaining <= 0) {
                        throw new SocketException("Test read timed out");
                    }
                    TimeUnit.NANOSECONDS.timedWait(this, remaining);
                } catch (InterruptedException e) {
                    // Socket reads need the socket to close; interruption alone is insufficient.
                }
            }
            blocked = false;
            if (closed) {
                throw new SocketException("Socket closed");
            }
            int count = Math.min(len, bytes.size());
            for (int i = 0; i < count; i++) {
                b[off + i] = bytes.remove();
            }
            consumed += count;
            return count;
        }

        @Override
        public int read() throws IOException {
            byte[] b = new byte[1];
            read(b, 0, 1);
            return b[0] & 0xff;
        }

        @Override
        public synchronized void close() {
            closed = true;
            notifyAll();
        }
    }

    public static final class BlockingOutput extends OutputStream {
        public volatile boolean stall;
        public volatile boolean blocked;
        private boolean closed;

        @Override
        public synchronized void write(byte[] b, int off, int len) throws IOException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (stall && !closed) {
                blocked = true;
                try {
                    long remaining = deadline - System.nanoTime();
                    if (remaining <= 0) {
                        throw new SocketException("Test write timed out");
                    }
                    TimeUnit.NANOSECONDS.timedWait(this, remaining);
                } catch (InterruptedException e) {
                    // As with socket writes, only closing the stream unblocks this write.
                }
            }
            blocked = false;
            if (closed) {
                throw new SocketException("Socket closed");
            }
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[] {(byte) b}, 0, 1);
        }

        @Override
        public synchronized void close() {
            closed = true;
            notifyAll();
        }
    }

    private static final class TestSocketFactory extends SocketFactory {
        private final Socket socket;

        private TestSocketFactory(Socket socket) {
            this.socket = socket;
        }

        @Override
        public Socket createSocket(String host, int port) {
            return socket;
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress local, int localPort) {
            return socket;
        }

        @Override
        public Socket createSocket(InetAddress host, int port) {
            return socket;
        }

        @Override
        public Socket createSocket(InetAddress host, int port, InetAddress local, int localPort) {
            return socket;
        }
    }
}
