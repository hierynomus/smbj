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
import com.hierynomus.mssmb2.SMB2ChangeNotifyFlags;
import com.hierynomus.mssmb2.SMB2CompletionFilter;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2GlobalCapability;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.SMB3EncryptedPacketData;
import com.hierynomus.mssmb2.messages.SMB2ChangeNotifyRequest;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.mssmb2.messages.SMB2TreeDisconnect;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor;
import com.hierynomus.smbj.testing.Utils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static com.hierynomus.mssmb2.SMB2MessageCommandCode.*;
import static com.hierynomus.mssmb2.SMB2MessageFlag.*;
import static com.hierynomus.smbj.connection.ResponseTestPackets.*;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(10)
public class EncryptedResponseValidationTest {
    private static final SecretKey SIGNING_KEY = new SecretKeySpec(KEY.getEncoded(), SMBSessionBuilder.AES_128_CMAC_ALGORITHM);
    private static final SecretKey ENCRYPTION_KEY = new SecretKeySpec(KEY.getEncoded(), "AES");
    private static final SecretKey DECRYPTION_KEY = new SecretKeySpec(new byte[] {
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
    }, "AES");
    private static final byte[] EMPTY_ERROR = new byte[] {9, 0, 0, 0, 0, 0, 0, 0};
    private static final byte[] EMPTY_NOTIFY = new byte[] {9, 0, 0, 0, 0, 0, 0, 0};

    @ParameterizedTest
    @CsvSource({"true, 0", "true, 1", "true, 2", "true, 3", "true, 4", "true, 5", "true, 6", "true, 7", "true, 8",
        "false, 0", "false, 1", "false, 2", "false, 3", "false, 4", "false, 5", "false, 6", "false, 7", "false, 8"})
    public void shouldAcceptUnsignedInterimsBeforeProtectedFinal(boolean encrypted, int padding) throws Exception {
        try (TestConnection test = new TestConnection(encrypted)) {
            SMB2Packet packet = notifyRequest();
            Future<SMB2Packet> future = test.session.send(packet);
            Request request = test.request(packet);
            assertEquals(encrypted, request.isEncrypted());
            int credits = test.connection.sequenceWindow.available();
            byte[] body = Arrays.copyOf(EMPTY_ERROR, EMPTY_ERROR.length + padding);
            Arrays.fill(body, EMPTY_ERROR.length, body.length, (byte) 0x55);
            SMB2Packet pending = pending(packet, body);

            test.receivePlain(pending);

            assertFalse(future.isDone());
            assertEquals(1234, request.getAsyncId());
            assertEquals(credits + 3, test.connection.sequenceWindow.available());
            pending.getHeader().setAsyncId(5678);
            test.receivePlain(pending);
            assertFalse(future.isDone());
            assertEquals(5678, request.getAsyncId());
            assertEquals(credits + 6, test.connection.sequenceWindow.available());

            SMB2Packet finalResponse = reply(packet, NtStatus.STATUS_SUCCESS, EMPTY_NOTIFY);
            finalResponse.getHeader().setFlag(SMB2_FLAGS_ASYNC_COMMAND);
            finalResponse.getHeader().setAsyncId(5678);
            test.receiveProtected(finalResponse);

            assertEquals(NtStatus.STATUS_SUCCESS.getValue(), future.get(1, TimeUnit.SECONDS).getHeader().getStatusCode());
            assertNull(test.request(packet));
            assertTrue(test.connection.isConnected());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void shouldCompleteProtectedCancelledResponseAfterInterimAndCancel(boolean encrypted) throws Exception {
        try (TestConnection test = new TestConnection(encrypted)) {
            SMB2Packet packet = notifyRequest();
            Future<SMB2Packet> future = test.session.send(packet);
            Request request = test.request(packet);
            test.receivePlain(pending(packet, EMPTY_ERROR));
            int credits = test.connection.sequenceWindow.available();

            assertTrue(future.cancel(true));

            SMB2Packet cancel = test.transport.sent.get(1);
            assertEquals(SMB2_CANCEL, cancel.getHeader().getMessage());
            assertEquals(packet.getHeader().getMessageId(), cancel.getSequenceNumber());
            assertEquals(1234, cancel.getHeader().getAsyncId());
            assertEquals(encrypted, cancel instanceof PacketEncryptor.EncryptedPacketWrapper);
            assertEquals(credits, test.connection.sequenceWindow.available());
            assertSame(request, test.request(packet));
            assertFalse(request.getPromise().isFulfilled());

            SMB2Packet cancelled = reply(packet, NtStatus.STATUS_CANCELLED, EMPTY_ERROR);
            cancelled.getHeader().setFlag(SMB2_FLAGS_ASYNC_COMMAND);
            cancelled.getHeader().setAsyncId(1234);
            test.receiveProtected(cancelled);

            assertEquals(NtStatus.STATUS_CANCELLED.getValue(), future.get(1, TimeUnit.SECONDS).getHeader().getStatusCode());
            assertNull(test.request(packet));
            assertTrue(test.connection.isConnected());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void shouldCompleteProtectedTreeDisconnectAndLogoff(boolean encrypted) throws Exception {
        try (TestConnection test = new TestConnection(encrypted)) {
            SMB2TreeDisconnect packet = new SMB2TreeDisconnect(SMB2Dialect.SMB_3_0, SESSION_ID, 1);
            Future<SMB2Packet> future = test.session.send(packet);
            assertEquals(encrypted, test.request(packet).isEncrypted());
            test.receiveProtected(reply(packet, NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0}));
            assertTrue(future.get(1, TimeUnit.SECONDS) instanceof SMB2TreeDisconnect);

            test.transport.answerLogoff = true;
            test.session.logoff();

            assertEquals(SMB2_LOGOFF, test.transport.sent.get(1).getHeader().getMessage());
            assertEquals(encrypted, test.transport.sent.get(1) instanceof PacketEncryptor.EncryptedPacketWrapper);
            assertNull(test.connection.getSessionTable().find(SESSION_ID));
            assertTrue(test.connection.isConnected());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void shouldDiscardUncorrelatedOrDataBearingInterims(boolean encrypted) throws Exception {
        try (TestConnection test = new TestConnection(encrypted)) {
            SMB2Packet packet = notifyRequest();
            Future<SMB2Packet> future = test.session.send(packet);
            Request request = test.request(packet);
            int credits = test.connection.sequenceWindow.available();
            List<SMB2Packet> invalid = new ArrayList<>();
            SMB2Packet unknown = pending(packet, EMPTY_ERROR);
            unknown.getHeader().setMessageId(packet.getHeader().getMessageId() + 1000);
            invalid.add(unknown);
            SMB2Packet wrongCommand = pending(packet, EMPTY_ERROR);
            wrongCommand.getHeader().setMessageType(SMB2_READ);
            invalid.add(wrongCommand);
            SMB2Packet wrongSession = pending(packet, EMPTY_ERROR);
            wrongSession.getHeader().setSessionId(0);
            invalid.add(wrongSession);
            invalid.add(pending(packet, new byte[] {9, 0, 0, 0, 1, 0, 0, 0, 42}));
            invalid.add(pending(packet, Arrays.copyOf(EMPTY_ERROR, 17)));
            invalid.add(pending(packet, new byte[8]));
            invalid.add(pending(packet, new byte[] {9, 0, 1, 0, 0, 0, 0, 0}));
            invalid.add(pending(packet, Arrays.copyOf(EMPTY_ERROR, 7)));
            SMB2Packet synchronous = reply(packet, NtStatus.STATUS_PENDING, EMPTY_ERROR);
            invalid.add(synchronous);

            for (SMB2Packet interim : invalid) {
                test.receivePlain(interim);
                assertFalse(future.isDone());
                assertEquals(0, request.getAsyncId());
                assertEquals(credits, test.connection.sequenceWindow.available());
                assertSame(request, test.request(packet));
                assertTrue(test.connection.isConnected());
            }
            test.receiveProtected(reply(packet, NtStatus.STATUS_SUCCESS, EMPTY_NOTIFY));
            assertEquals(NtStatus.STATUS_SUCCESS.getValue(), future.get(1, TimeUnit.SECONDS).getHeader().getStatusCode());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void shouldAbortAllRequestsForPlainFinalToEncryptedRequest(boolean signed) throws Exception {
        try (TestConnection test = new TestConnection(true)) {
            SMB2Packet first = notifyRequest();
            Future<SMB2Packet> firstFuture = test.session.send(first);
            Future<SMB2Packet> secondFuture = test.session.send(notifyRequest());
            byte[] data = test.plainBytes(reply(first, NtStatus.STATUS_SUCCESS, EMPTY_NOTIFY), signed);
            if (signed) {
                assertTrue(test.signatory.verify(new SMB2PacketData(data), SIGNING_KEY));
            }

            TransportException violation = assertThrows(TransportException.class,
                () -> test.connection.handle(new SMB2PacketData(data)));

            assertTrue(violation.getMessage().contains("Unencrypted final response"));
            test.assertAborted(violation, firstFuture, secondFuture);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1})
    public void shouldAbortBeforeDeliveringAnyMemberWithMismatchedTransformSessionId(int foreignMember) throws Exception {
        try (TestConnection test = new TestConnection(true)) {
            SMB2Packet first = notifyRequest();
            SMB2Packet second = notifyRequest();
            Future<SMB2Packet> firstFuture = test.session.send(first);
            Future<SMB2Packet> secondFuture = test.session.send(second);
            SMB2Packet[] replies = new SMB2Packet[] {
                reply(first, NtStatus.STATUS_SUCCESS, EMPTY_NOTIFY), reply(second, NtStatus.STATUS_SUCCESS, EMPTY_NOTIFY)
            };
            replies[foreignMember].getHeader().setSessionId(SESSION_ID + 1);
            byte[] data = frame(replies);

            TransportException violation = assertThrows(TransportException.class,
                () -> test.connection.handle(test.encryptedFrame(data, SESSION_ID)));

            assertTrue(violation.getMessage().contains("transform session ID"));
            test.assertAborted(violation, firstFuture, secondFuture);
        }
    }

    @Test
    public void shouldAbortIfFinalWasEncryptedForAnotherSession() throws Exception {
        try (TestConnection test = new TestConnection(true)) {
            SMB2Packet packet = notifyRequest();
            Future<SMB2Packet> future = test.session.send(packet);
            Session other = new Session(test.connection, null, null, null, null, null, null);
            other.setSessionId(SESSION_ID + 1);
            other.getSessionContext().setDecryptionKey(ENCRYPTION_KEY);
            test.connection.getSessionTable().registerSession(other.getSessionId(), other);
            SMB2Packet response = reply(packet, NtStatus.STATUS_SUCCESS, EMPTY_NOTIFY);
            response.getHeader().setSessionId(other.getSessionId());

            TransportException violation = assertThrows(TransportException.class,
                () -> test.connection.handle(test.encryptedFrame(serialize(response), other.getSessionId(), ENCRYPTION_KEY)));

            assertTrue(violation.getMessage().contains("differs from request"));
            test.assertAborted(violation, future);
        }
    }

    @Test
    public void shouldAcceptPlainFinalForRequestSentPlainOnEncryptingSession() throws Exception {
        try (TestConnection test = new TestConnection(true)) {
            SMB2Packet packet = notifyRequest();
            Future<SMB2Packet> future = test.connection.send(packet);
            assertFalse(test.request(packet).isEncrypted());

            test.receivePlain(reply(packet, NtStatus.STATUS_SUCCESS, EMPTY_NOTIFY));

            assertEquals(NtStatus.STATUS_SUCCESS.getValue(), future.get(1, TimeUnit.SECONDS).getHeader().getStatusCode());
            assertTrue(test.connection.isConnected());
        }
    }

    @Test
    public void shouldRequireEncryptedFinalWhenOnlyThisRequestRequiresEncryption() throws Exception {
        try (TestConnection test = new TestConnection(false)) {
            test.session.getSessionContext().setEncryptionKey(ENCRYPTION_KEY);
            assertFalse(test.session.shouldEncryptData());
            SMB2Packet packet = notifyRequest();
            Future<SMB2Packet> future = test.session.send(packet, true);
            assertTrue(test.request(packet).isEncrypted());
            byte[] data = test.plainBytes(reply(packet, NtStatus.STATUS_SUCCESS, EMPTY_NOTIFY), true);

            TransportException violation = assertThrows(TransportException.class,
                () -> test.connection.handle(new SMB2PacketData(data)));

            test.assertAborted(violation, future);
        }
    }

    @Test
    public void shouldRecordEncryptionWhenClientPrefersIt() throws Exception {
        try (TestConnection test = new TestConnection(false)) {
            test.session.getSessionContext().setEncryptionKey(ENCRYPTION_KEY);
            test.connection.getConnectionContext().getClientCapabilities().add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_ENCRYPTION);
            test.connection.getConnectionContext().getServer().getCapabilities().add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_ENCRYPTION);
            assertFalse(test.session.getSessionContext().isEncryptData());
            assertTrue(test.session.shouldEncryptData());
            SMB2Packet packet = notifyRequest();
            Future<SMB2Packet> future = test.session.send(packet);
            assertTrue(test.transport.sent.get(0) instanceof PacketEncryptor.EncryptedPacketWrapper);
            assertTrue(test.request(packet).isEncrypted());

            test.connection.handle(test.encryptedFrame(serialize(reply(packet, NtStatus.STATUS_SUCCESS, EMPTY_NOTIFY)), SESSION_ID));

            assertEquals(NtStatus.STATUS_SUCCESS.getValue(), future.get(1, TimeUnit.SECONDS).getHeader().getStatusCode());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void shouldDiscardUnsolicitedOplockBreakWithoutTouchingRequests(boolean encryptedNotification) throws Exception {
        try (TestConnection test = new TestConnection(true)) {
            SMB2Packet packet = notifyRequest();
            Future<SMB2Packet> future = test.session.send(packet);
            Request request = test.request(packet);
            int credits = test.connection.sequenceWindow.available();
            for (int size : new int[] {24, 44}) {
                byte[] body = new byte[size];
                body[0] = (byte) size;
                SMB2Packet notification = response(-1, SMB2_OPLOCK_BREAK, 0, false, NtStatus.STATUS_SUCCESS, body);
                if (encryptedNotification) {
                    test.connection.handle(test.encryptedFrame(serialize(notification), SESSION_ID));
                } else {
                    test.receivePlain(notification);
                }
                assertFalse(future.isDone());
                assertSame(request, test.request(packet));
                assertEquals(credits, test.connection.sequenceWindow.available());
                assertEquals(0, request.getAsyncId());
                assertTrue(test.connection.isConnected());
            }
        }
    }

    private static SMB2Packet notifyRequest() {
        return new SMB2ChangeNotifyRequest(SMB2Dialect.SMB_3_0, SESSION_ID, 1, new SMB2FileId(),
            EnumSet.noneOf(SMB2CompletionFilter.class), EnumSet.noneOf(SMB2ChangeNotifyFlags.class), 1024);
    }

    private static SMB2Packet reply(SMB2Packet request, NtStatus status, byte[] body) {
        return response(request.getHeader().getMessageId(), request.getHeader().getMessage(), SESSION_ID, false, status, body);
    }

    private static SMB2Packet pending(SMB2Packet request, byte[] body) {
        SMB2Packet pending = reply(request, NtStatus.STATUS_PENDING, body);
        pending.getHeader().setFlag(SMB2_FLAGS_ASYNC_COMMAND);
        pending.getHeader().setAsyncId(1234);
        return pending;
    }

    private static byte[] serialize(SMB2Packet packet) {
        SMBBuffer buffer = new SMBBuffer();
        packet.write(buffer);
        byte[] data = buffer.getCompactData();
        // The production header writer emits request status and credit fields.
        putUInt32(data, 8, packet.getHeader().getStatusCode());
        data[14] = (byte) packet.getHeader().getCreditResponse();
        data[15] = (byte) (packet.getHeader().getCreditResponse() >>> 8);
        return data;
    }

    private static SMB2Packet rawPacket(final byte[] data, long sessionId) {
        SMB2Packet packet = new SMB2Packet() {
            @Override
            public void write(SMBBuffer buffer) {
                buffer.putRawBytes(data);
            }
        };
        packet.getHeader().setSessionId(sessionId);
        return packet;
    }

    private static class TestConnection implements Closeable {
        private final SMBClient client;
        private final Connection connection;
        private final Session session;
        private final PacketSignatory signatory = new PacketSignatory(new BCSecurityProvider());
        private final PacketEncryptor encryptor = new PacketEncryptor(new BCSecurityProvider());
        private final RecordingTransport transport = new RecordingTransport();
        private final boolean encrypted;

        TestConnection(boolean encrypted) throws Exception {
            this.encrypted = encrypted;
            DefaultPacketProcessor processor = new DefaultPacketProcessor();
            SmbConfig config = Utils.configBuilder(request -> {
                if (request.getHeader().getMessage() == SMB2_NEGOTIATE) {
                    SMB2NegotiateResponse response = (SMB2NegotiateResponse) processor.process(request);
                    response.setDialect(SMB2Dialect.SMB_3_0);
                    return response;
                }
                return null;
            }).withDialects(SMB2Dialect.SMB_3_0).withSecurityProvider(new BCSecurityProvider()).build();
            SMBEventBus bus = new SMBEventBus();
            client = new SMBClient(config, bus);
            connection = client.connect("127.0.0.1");
            connection.transport.disconnect();
            connection.transport = transport;
            encryptor.init(connection.getConnectionContext());
            session = new Session(connection, config, null, bus, null, signatory, encryptor);
            session.setSessionId(SESSION_ID);
            session.getSessionContext().setSigningKey(SIGNING_KEY);
            session.getSessionContext().setSigningRequired(!encrypted);
            session.getSessionContext().setEncryptData(encrypted);
            session.getSessionContext().setEncryptionKey(encrypted ? ENCRYPTION_KEY : null);
            session.getSessionContext().setDecryptionKey(DECRYPTION_KEY);
            connection.getSessionTable().registerSession(SESSION_ID, session);
        }

        Request request(SMB2Packet packet) {
            return connection.outstandingRequests.getRequestByMessageId(packet.getHeader().getMessageId());
        }

        byte[] plainBytes(SMB2Packet packet, boolean signed) {
            if (signed) {
                packet.getHeader().setFlag(SMB2_FLAGS_SIGNED);
            }
            byte[] data = serialize(packet);
            if (signed) {
                SMBBuffer buffer = new SMBBuffer();
                signatory.sign(rawPacket(data, SESSION_ID), SIGNING_KEY).write(buffer);
                data = buffer.getCompactData();
            }
            return data;
        }

        SMB3EncryptedPacketData encryptedFrame(byte[] data, long sessionId) throws Exception {
            return encryptedFrame(data, sessionId, DECRYPTION_KEY);
        }

        SMB3EncryptedPacketData encryptedFrame(byte[] data, long sessionId, SecretKey key) throws Exception {
            SMBBuffer buffer = new SMBBuffer();
            encryptor.encrypt(rawPacket(data, sessionId), key).write(buffer);
            return new SMB3EncryptedPacketData(buffer.getCompactData());
        }

        void receivePlain(SMB2Packet packet) throws Exception {
            connection.handle(new SMB2PacketData(plainBytes(packet, false)));
        }

        void receiveProtected(SMB2Packet packet) throws Exception {
            if (encrypted) {
                connection.handle(encryptedFrame(serialize(packet), SESSION_ID));
            } else {
                connection.handle(new SMB2PacketData(plainBytes(packet, true)));
            }
        }

        void assertAborted(TransportException violation, Future<?>... futures) throws Exception {
            assertFalse(connection.isConnected());
            assertEquals(1, transport.disconnects);
            for (Future<?> future : futures) {
                assertSame(violation, AbortTestConnection.transportFailure(future));
            }
            assertThrows(TransportException.class, () -> session.send(notifyRequest()));
        }

        @Override
        public void close() throws IOException {
            connection.close(true);
            client.close();
        }

        private class RecordingTransport implements TransportLayer<SMBPacket<?, ?>> {
            private final List<SMB2Packet> sent = new ArrayList<>();
            private int disconnects;
            private boolean answerLogoff;

            @Override
            public void write(SMBPacket<?, ?> packet) throws TransportException {
                SMB2Packet request = (SMB2Packet) packet;
                sent.add(request);
                packet.write(new SMBBuffer());
                if (answerLogoff && request.getHeader().getMessage() == SMB2_LOGOFF) {
                    assertSame(session, connection.getSessionTable().find(SESSION_ID));
                    assertEquals(encrypted, request(request).isEncrypted());
                    try {
                        receiveProtected(reply(request, NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0}));
                    } catch (Exception e) {
                        throw new TransportException(e);
                    }
                }
            }

            @Override
            public void connect(InetSocketAddress address) {
            }

            @Override
            public void disconnect() {
                disconnects++;
            }

            @Override
            public boolean isConnected() {
                return disconnects == 0;
            }
        }
    }
}
