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
package com.hierynomus.smbj.connection

import com.hierynomus.mssmb2.SMB2MessageCommandCode
import com.hierynomus.mssmb2.SMB2Packet
import com.hierynomus.protocol.transport.PacketHandlers
import com.hierynomus.protocol.transport.TransportException
import com.hierynomus.protocol.transport.TransportLayer
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor
import com.hierynomus.smbj.testing.PacketProcessor.NoOpPacketProcessor
import com.hierynomus.smbj.testing.StubAuthenticator
import com.hierynomus.smbj.testing.StubTransportLayerFactory
import com.hierynomus.smbj.transport.TransportLayerFactory
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpPacketReader
import spock.lang.Specification

import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit

/**
 * A read error in the packet reader (e.g. "Read timed out" on an idle socket) makes the reader
 * call {@code handleError}. A graceful {@code close()} from there logs off trees and sessions over
 * the broken transport; nobody reads the responses anymore, so every logoff waits for the full
 * transact timeout. On a connection leased more than once, {@code close()} only releases one lease:
 * {@code isConnected()} stays {@code true} and the next request is sent over a transport without a
 * reader.
 *
 * The transport used here answers through the stub until the "server" goes silent; after that it
 * accepts packets but answers none (like a socket without a reader).
 */
class ConnectionReadErrorSpec extends Specification {

    static final long TRANSACT_TIMEOUT_MS = 2000

    List<SMB2MessageCommandCode> written = Collections.synchronizedList([])
    volatile boolean silent = false
    SMBClient client

    def cleanup() {
        client?.close()
    }

    def "a read error closes the connection at once instead of logging off over the dead transport"() {
        given:
        def connection = connect()
        def session = connection.authenticate(new AuthenticationContext("user", "pass".toCharArray(), null))
        session.connectShare("share")
        silent = true
        int before = written.size()

        when:
        long took = handleErrorInReaderThread(connection)

        then: "no waiting for responses that nobody reads"
        took < TRANSACT_TIMEOUT_MS / 2
        !connection.isConnected()
        and: "no logoff over the broken transport"
        written.subList(before, written.size()).findAll {
            it == SMB2MessageCommandCode.SMB2_TREE_DISCONNECT || it == SMB2MessageCommandCode.SMB2_LOGOFF
        }.isEmpty()
    }

    def "after a read error a shared connection is not connected and a new request fails at once"() {
        given: "the connection is leased twice (two users of the same connection)"
        def connection = connect()
        assert client.connect("localhost").is(connection)
        def session = connection.authenticate(new AuthenticationContext("user", "pass".toCharArray(), null))
        silent = true
        handleErrorInReaderThread(connection)

        when:
        long t0 = System.nanoTime()
        session.connectShare("other")

        then:
        def e = thrown(Exception)
        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0) < TRANSACT_TIMEOUT_MS / 2
        firstTransportException(e) instanceof TransportException
        !connection.isConnected()
    }

    def "after a read error the client builds a new connection"() {
        given:
        def connection = connect()
        client.connect("localhost")
        silent = true
        handleErrorInReaderThread(connection)
        silent = false

        when:
        def next = client.connect("localhost")

        then:
        !next.is(connection)
        next.isConnected()
    }

    def "a read timeout in the packet reader itself closes the connection at once"() {
        given: "the real path: DirectTcpPacketReader -> PacketReader.run -> handleError"
        def connection = connect()
        def session = connection.authenticate(new AuthenticationContext("user", "pass".toCharArray(), null))
        session.connectShare("share")
        silent = true
        int before = written.size()
        def timingOut = new InputStream() {
            @Override
            int read() throws IOException {
                throw new SocketTimeoutException("Read timed out")
            }
        }
        def reader = new DirectTcpPacketReader("localhost", timingOut, null, connection)

        when:
        long t0 = System.nanoTime()
        reader.start()
        while (connection.isConnected() && TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0) < TRANSACT_TIMEOUT_MS * 5) {
            Thread.sleep(10)
        }

        then:
        !connection.isConnected()
        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0) < TRANSACT_TIMEOUT_MS / 2
        written.subList(before, written.size()).findAll {
            it == SMB2MessageCommandCode.SMB2_TREE_DISCONNECT || it == SMB2MessageCommandCode.SMB2_LOGOFF
        }.isEmpty()
    }

    def "control: requests outstanding at the read error fail at once"() {
        given:
        def connection = connect()
        def session = connection.authenticate(new AuthenticationContext("user", "pass".toCharArray(), null))
        silent = true
        Throwable failure = null
        long took = -1
        def waiter = Thread.start {
            long t0 = System.nanoTime()
            try {
                session.connectShare("share")
            } catch (Throwable t) {
                failure = t
            }
            took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0)
        }
        while (!written.contains(SMB2MessageCommandCode.SMB2_TREE_CONNECT)) {
            Thread.sleep(10)
        }

        when:
        handleErrorInReaderThread(connection)
        waiter.join(TRANSACT_TIMEOUT_MS * 3)

        then:
        failure != null
        took >= 0 && took < TRANSACT_TIMEOUT_MS / 2
    }

    private Connection connect() {
        def processor = new DefaultPacketProcessor().wrap(new NoOpPacketProcessor())
        def config = SmbConfig.builder()
            .withTransportLayerFactory(new SilenceableTransportFactory(new StubTransportLayerFactory(processor)))
            .withAuthenticators(new StubAuthenticator.Factory())
            .withTransactTimeout(TRANSACT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .build()
        client = new SMBClient(config)
        return client.connect("localhost")
    }

    /** Calls handleError from a separate thread, like the packet reader does, and measures how long it takes. */
    private static long handleErrorInReaderThread(Connection connection) {
        long took = -1
        def reader = Thread.start("Packet Reader for localhost") {
            long t0 = System.nanoTime()
            connection.handleError(new TransportException(new SocketTimeoutException("Read timed out")))
            took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0)
        }
        reader.join(TRANSACT_TIMEOUT_MS * 10)
        assert !reader.isAlive(): "handleError must return"
        return took
    }

    private static Throwable firstTransportException(Throwable t) {
        // the TransportException may carry a cause of its own; return the first one in the chain
        Throwable c = t
        while (c != null) {
            if (c instanceof TransportException) {
                return c
            }
            c = c.cause
        }
        return t
    }

    /**
     * Answers through the stub while the server is talking; after that it accepts packets and
     * answers none. After {@code disconnect()} every write fails, as with
     * {@code DirectTcpTransport}.
     */
    class SilenceableTransportFactory implements TransportLayerFactory {
        private final StubTransportLayerFactory inner

        SilenceableTransportFactory(StubTransportLayerFactory inner) {
            this.inner = inner
        }

        @Override
        TransportLayer createTransportLayer(PacketHandlers handlers, SmbConfig config) {
            TransportLayer delegate = inner.createTransportLayer(handlers, config)
            return new TransportLayer() {
                boolean connected

                @Override
                void write(com.hierynomus.protocol.Packet packet) throws TransportException {
                    if (!connected) {
                        throw new TransportException("Cannot write " + packet + " as transport is disconnected")
                    }
                    written << ((SMB2Packet) packet).header.message
                    if (!silent) {
                        delegate.write(packet)
                    }
                }

                @Override
                void connect(InetSocketAddress remoteAddress) throws IOException {
                    connected = true
                    delegate.connect(remoteAddress)
                }

                @Override
                void disconnect() throws IOException {
                    connected = false
                    delegate.disconnect()
                }

                @Override
                boolean isConnected() {
                    return connected
                }
            }
        }
    }
}
