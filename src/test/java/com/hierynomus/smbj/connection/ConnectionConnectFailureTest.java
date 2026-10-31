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

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smb.SMBPacketData;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.transport.PacketReader;
import com.hierynomus.smbj.transport.TransportLayerFactory;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.SocketFactory;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.hierynomus.mssmb2.SMB2MessageCommandCode.SMB2_NEGOTIATE;
import static com.hierynomus.smbj.connection.AbortTestConnection.echo;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Timeout(10)
public class ConnectionConnectFailureTest {
    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void shouldAbortAfterNegotiateErrorStatus(boolean throughClient) throws Exception {
        assertFailedConnect(throughClient, NtStatus.STATUS_ACCESS_DENIED, new byte[] {9, 0, 0, 0, 0, 0, 0, 0, 0},
            SMBApiException.class, "Failure during dialect negotiation");
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void shouldAbortAfterMalformedNegotiateContexts(boolean throughClient) throws Exception {
        SMBBuffer body = new SMBBuffer();
        body.putUInt16(65); // StructureSize
        body.putUInt16(1); // SecurityMode
        body.putUInt16(0x0311); // DialectRevision
        body.putUInt16(1); // NegotiateContextCount
        body.putReserved(16); // ServerGuid
        body.putUInt32(0); // Capabilities
        body.putUInt32(65536); // MaxTransactSize
        body.putUInt32(65536); // MaxReadSize
        body.putUInt32(65536); // MaxWriteSize
        body.putReserved(16); // SystemTime, ServerStartTime
        body.putUInt16(0); // SecurityBufferOffset
        body.putUInt16(0); // SecurityBufferLength
        body.putUInt32(128); // NegotiateContextOffset
        body.putUInt16(2); // SMB2_ENCRYPTION_CAPABILITIES
        body.putUInt16(2); // DataLength
        body.putReserved(4);
        body.putUInt16(0); // Invalid CipherCount: the server must select exactly one.

        assertFailedConnect(throughClient, NtStatus.STATUS_SUCCESS, body.getCompactData(), IllegalStateException.class,
            "The SMB2EncryptionCapabilities NegotiateContext does not contain exactly 1 cipher");
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void shouldRethrowOriginalFailureWhenCleanupFails(boolean unchecked) throws Exception {
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        Exception failure = unchecked ? new IllegalStateException("Negotiation failed") : new TransportException("Negotiation failed");
        when(transport.isConnected()).thenReturn(false, true);
        doThrow(failure).when(transport).write(any());
        doThrow(new IOException("Disconnect failed")).when(transport).disconnect();
        TransportLayerFactory<SMBPacketData<?>, SMBPacket<?, ?>> factory = (handlers, config) -> transport;
        SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_2_1)
            .withTransportLayerFactory(factory).build();
        SMBEventBus bus = spy(new SMBEventBus());
        try (SMBClient client = new SMBClient(config, bus)) {
            Connection connection = new Connection(config, client, bus, client.getServerList());

            assertSame(failure, assertThrows(Exception.class, () -> connection.connect("127.0.0.1", 445)));

            verify(bus).unsubscribe(connection);
            assertTrue(((ExecutorService) field(LeaseManager.class, "breakExecutor", connection.getLeaseManager())).isShutdown());
        }
    }

    private static void assertFailedConnect(boolean throughClient, NtStatus status, byte[] body,
                                            Class<? extends RuntimeException> expectedType, String message) throws Exception {
        AbortTestConnection.TestSocket socket = new AbortTestConnection.TestSocket();
        SocketFactory sockets = mock(SocketFactory.class);
        when(sockets.createSocket(anyString(), anyInt())).thenReturn(socket);
        AtomicReference<Connection> created = new AtomicReference<>();
        AtomicReference<DirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>>> transport = new AtomicReference<>();
        TransportLayerFactory<SMBPacketData<?>, SMBPacket<?, ?>> factory = (handlers, config) -> {
            created.set((Connection) handlers.getReceiver());
            DirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>> direct =
                new DirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>>(sockets, 0, handlers) {
                    @Override
                    public void write(SMBPacket<?, ?> packet) throws TransportException {
                        super.write(packet);
                        SMB2Packet response = ResponseTestPackets.response(((SMB2Packet) packet).getSequenceNumber(), SMB2_NEGOTIATE,
                            0, false, status, body);
                        socket.input.offer(AbortTestConnection.frame(response));
                    }
                };
            transport.set(direct);
            return direct;
        };
        SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1)
            .withTransportLayerFactory(factory).withTransactTimeout(1, TimeUnit.SECONDS).build();
        SMBEventBus bus = spy(new SMBEventBus());
        try (SMBClient client = new SMBClient(config, bus)) {
            Connection connection = throughClient ? null : new Connection(config, client, bus, client.getServerList());
            try {
                RuntimeException failure = assertThrows(expectedType, () -> {
                    if (throughClient) {
                        client.connect("127.0.0.1");
                    } else {
                        connection.connect("127.0.0.1", 445);
                    }
                });

                assertTrue(failure.getMessage().contains(message));
                Connection failed = created.get();
                Object reader = field(DirectTcpTransport.class, "packetReaderThread", transport.get());
                Thread thread = (Thread) field(PacketReader.class, "thread", reader);
                thread.join(1000);
                assertFalse(thread.isAlive());
                assertTrue(socket.isClosed());
                assertEquals(1, socket.closeCalls.get());
                assertFalse(failed.isConnected());
                assertTrue(((Map<?, ?>) field(SMBClient.class, "connectionTable", client)).isEmpty());
                verify(bus).unsubscribe(failed);
                ExecutorService executor = (ExecutorService) field(LeaseManager.class, "breakExecutor", failed.getLeaseManager());
                assertTrue(executor.isShutdown());
                assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS));
                assertSame(failure, assertThrows(TransportException.class, () -> failed.send(echo())).getCause());
            } finally {
                // Also stop the reader when the cleanup regression under test causes an assertion to fail.
                if (created.get() != null) {
                    created.get().close(true);
                }
            }
        }
    }

    private static Object field(Class<?> owner, String name, Object instance) throws Exception {
        Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(instance);
    }
}
