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
import com.hierynomus.mssmb2.SMB2DecryptedPacketData;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2MessageFlag;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.SMB2PacketHeader;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.testing.PacketProcessor.NoOpPacketProcessor;
import com.hierynomus.smbj.testing.Utils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Future;

import static com.hierynomus.mssmb2.SMB2MessageCommandCode.*;
import static com.hierynomus.smbj.connection.ResponseTestPackets.*;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(10)
public class ResponseValidationTest {
    private SMBClient client;
    private Connection connection;
    private Session session;

    @BeforeEach
    public void setUp() throws Exception {
        SmbConfig config = Utils.config(new NoOpPacketProcessor());
        client = new SMBClient(config);
        connection = client.connect("127.0.0.1");
        session = new Session(connection, config, null, null, null, null, null);
        session.setSessionId(SESSION_ID);
        session.getSessionContext().setSessionKey(new SecretKeySpec(KEY.getEncoded(), KEY.getAlgorithm()));
        session.getSessionContext().setSigningRequired(true);
        connection.getSessionTable().registerSession(SESSION_ID, session);
    }

    @AfterEach
    public void tearDown() {
        client.close();
    }

    @Test
    public void shouldCompleteBothRequestsForValidSignedCompound() throws Exception {
        Request first = request(1);
        Request second = request(2);
        int credits = connection.sequenceWindow.available();

        receive(frame(response(1), response(2)));

        assertResponse(first, 1);
        assertResponse(second, 2);
        assertEquals(credits + 6, connection.sequenceWindow.available());
    }

    @Test
    public void shouldDiscardWholeCompoundWithAppendedSessionZeroForgery() throws Exception {
        Request first = request(1);
        Request second = request(2);
        Request third = request(3);
        SMB2Packet forged = response(3, SMB2_ECHO, 0, true, NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0});
        byte[] data = frame(response(1), response(2), forged);
        Arrays.fill(data, 2 * MEMBER_SIZE + SMB2PacketHeader.SIGNATURE_OFFSET,
            2 * MEMBER_SIZE + SMB2PacketHeader.STRUCTURE_SIZE, (byte) 0x55);
        int credits = connection.sequenceWindow.available();

        receive(data);

        assertDiscarded(credits, first, second, third);
    }

    @Test
    public void shouldDiscardWholeCompoundWithForeignSession() throws Exception {
        Request first = request(1);
        Request second = request(2);
        SMB2Packet foreign = response(2, SMB2_ECHO, SESSION_ID + 1, true,
            NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0});
        int credits = connection.sequenceWindow.available();

        receive(frame(response(1), foreign));

        assertDiscarded(credits, first, second);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2})
    public void shouldDiscardWholeCompoundIfAnyMemberSignatureFails(int invalidMember) throws Exception {
        Request first = request(1);
        Request second = request(2);
        Request third = request(3);
        int credits = connection.sequenceWindow.available();
        byte[] original = frame(response(1), response(2), response(3));
        for (int offset : new int[] {SMB2PacketHeader.STRUCTURE_SIZE, SMB2PacketHeader.SIGNATURE_OFFSET}) {
            byte[] data = original.clone();
            data[invalidMember * MEMBER_SIZE + offset] ^= 1;
            receive(data);
            assertDiscarded(credits, first, second, third);
        }
    }

    @Test
    public void shouldDiscardWholeCompoundWithUnknownMessageId() throws Exception {
        Request first = request(1);
        int credits = connection.sequenceWindow.available();

        receive(frame(response(1), response(999)));

        assertDiscarded(credits, first);
    }

    @Test
    public void shouldDiscardCompoundWithDuplicateFinalResponse() throws Exception {
        Request outstanding = request(1);
        int credits = connection.sequenceWindow.available();

        receive(frame(response(1), response(1)));

        assertDiscarded(credits, outstanding);
    }

    @Test
    public void shouldDiscardSessionSetupResponseToReadRequest() throws Exception {
        Request read = request(1, SMB2_READ, SESSION_ID);
        int credits = connection.sequenceWindow.available();

        receive(frame(response(1, SMB2_SESSION_SETUP, SESSION_ID, true,
            NtStatus.STATUS_SUCCESS, new byte[8])));

        assertDiscarded(credits, read);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void shouldDiscardSessionZeroResponseToSessionRequest(boolean signed) throws Exception {
        Request outstanding = request(1);
        int credits = connection.sequenceWindow.available();

        receive(frame(response(1, SMB2_ECHO, 0, signed, NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0})));

        assertDiscarded(credits, outstanding);
    }

    @Test
    public void shouldDiscardMismatchedCommandAndContinueProcessing() throws Exception {
        Request outstanding = request(1);
        int credits = connection.sequenceWindow.available();
        // Without command correlation, the IOCTL error path casts the ECHO request to SMB2IoctlRequest.
        receive(frame(response(1, SMB2_IOCTL, SESSION_ID, true,
            NtStatus.STATUS_INVALID_PARAMETER, new byte[9])));
        assertDiscarded(credits, outstanding);

        receive(frame(response(1)));

        assertResponse(outstanding, 1);
        assertTrue(connection.isConnected());
    }

    @ParameterizedTest
    @ValueSource(ints = {8, 9, 10, 11, 12, 13, 14, 15, 16})
    public void shouldAcceptUnsignedPendingBeforeSignedFinal(int bodyLength) throws Exception {
        Request outstanding = request(1);
        byte[] body = new byte[bodyLength];
        body[0] = 9;
        SMB2Packet pending = response(1, SMB2_ECHO, SESSION_ID, false, NtStatus.STATUS_PENDING, body);
        pending.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND);
        pending.getHeader().setAsyncId(1234);
        receive(Arrays.copyOf(frame(pending), SMB2PacketHeader.STRUCTURE_SIZE + bodyLength));
        assertFalse(outstanding.getPromise().future().isDone());
        assertEquals(1234, outstanding.getAsyncId());

        SMB2Packet finalResponse = response(1);
        finalResponse.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND);
        finalResponse.getHeader().setAsyncId(1234);
        receive(frame(finalResponse));

        assertResponse(outstanding, 1);
    }

    @Test
    public void shouldAcceptPendingAndFinalInOneCompound() throws Exception {
        Request outstanding = request(1);
        SMB2Packet pending = response(1, SMB2_ECHO, SESSION_ID, false, NtStatus.STATUS_PENDING, new byte[] {9, 0, 0, 0, 0, 0, 0, 0});
        pending.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND);
        pending.getHeader().setAsyncId(1234);

        receive(frame(pending, response(1)));

        assertResponse(outstanding, 1);
        assertEquals(1234, outstanding.getAsyncId());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 42})
    public void shouldAcceptPaddedInterimBeforeAnotherRequestsSignedFinal(int errorData) throws Exception {
        Request first = request(1);
        Request second = request(2);
        int credits = connection.sequenceWindow.available();
        SMB2Packet pending = response(1, SMB2_ECHO, SESSION_ID, false, NtStatus.STATUS_PENDING,
            new byte[] {9, 0, 0, 0, 0, 0, 0, 0, (byte) errorData});
        pending.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND);
        pending.getHeader().setAsyncId(1234);

        receive(frame(pending, response(2)));

        assertFalse(first.getPromise().future().isDone());
        assertSame(first, connection.outstandingRequests.getRequestByMessageId(1L));
        assertEquals(1234, first.getAsyncId());
        assertResponse(second, 2);
        assertEquals(credits + 6, connection.sequenceWindow.available());
    }

    @ParameterizedTest
    @ValueSource(ints = {8, 9, 10, 11, 12, 13, 14, 15})
    public void shouldAcceptCompoundWithNonzeroInterimPadding(int paddingByte) throws Exception {
        Request first = request(1);
        Request second = request(2);
        int credits = connection.sequenceWindow.available();
        byte[] body = new byte[16];
        body[0] = 9;
        body[paddingByte] = 1;
        SMB2Packet pending = response(1, SMB2_ECHO, SESSION_ID, false, NtStatus.STATUS_PENDING, body);
        pending.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND);
        pending.getHeader().setAsyncId(1234);

        receive(frame(pending, response(2)));

        assertFalse(first.getPromise().future().isDone());
        assertSame(first, connection.outstandingRequests.getRequestByMessageId(1L));
        assertEquals(1234, first.getAsyncId());
        assertResponse(second, 2);
        assertEquals(credits + 6, connection.sequenceWindow.available());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void shouldAcceptPaddedInterimAtEndOfFrame(boolean compounded) throws Exception {
        Request first = request(1);
        Request second = request(2);
        int credits = connection.sequenceWindow.available();
        SMB2Packet pending = response(1, SMB2_ECHO, SESSION_ID, false, NtStatus.STATUS_PENDING,
            new byte[] {9, 0, 0, 0, 0, 0, 0, 0, 42});
        pending.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND);
        pending.getHeader().setAsyncId(1234);

        receive(compounded ? frame(response(2), pending) : frame(pending));

        assertFalse(first.getPromise().future().isDone());
        assertSame(first, connection.outstandingRequests.getRequestByMessageId(1L));
        assertEquals(1234, first.getAsyncId());
        if (compounded) {
            assertResponse(second, 2);
        } else {
            assertFalse(second.getPromise().future().isDone());
        }
        assertEquals(credits + (compounded ? 6 : 3), connection.sequenceWindow.available());

        receive(frame(response(1)));
        assertResponse(first, 1);
    }

    @Test
    public void shouldAcceptPaddedInterimInMiddleOfFrame() throws Exception {
        Request first = request(1);
        Request second = request(2);
        Request third = request(3);
        int credits = connection.sequenceWindow.available();
        byte[] body = new byte[16];
        Arrays.fill(body, 8, body.length, (byte) 0x55);
        body[0] = 9;
        SMB2Packet pending = response(2, SMB2_ECHO, SESSION_ID, false, NtStatus.STATUS_PENDING, body);
        pending.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND);
        pending.getHeader().setAsyncId(1234);

        receive(frame(response(1), pending, response(3)));

        assertResponse(first, 1);
        assertFalse(second.getPromise().future().isDone());
        assertSame(second, connection.outstandingRequests.getRequestByMessageId(2L));
        assertEquals(1234, second.getAsyncId());
        assertResponse(third, 3);
        assertEquals(credits + 9, connection.sequenceWindow.available());
    }

    @Test
    public void shouldDiscardUncorrelatedPendingResponse() throws Exception {
        Request outstanding = request(1);
        SMB2Packet pending = response(1, SMB2_ECHO, 0, false, NtStatus.STATUS_PENDING, new byte[] {9, 0, 0, 0, 0, 0, 0, 0});
        pending.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND);
        pending.getHeader().setAsyncId(1234);
        int credits = connection.sequenceWindow.available();

        receive(frame(pending));

        assertDiscarded(credits, outstanding);
        assertEquals(0, outstanding.getAsyncId());
    }

    @ParameterizedTest
    @ValueSource(ints = {8, 64, 73, 144, 216, Integer.MIN_VALUE, -8})
    public void shouldDiscardMalformedCompoundWithoutException(int nextCommand) throws Exception {
        Request first = request(1);
        Request second = request(2);
        int credits = connection.sequenceWindow.available();
        byte[] data = frame(response(1), response(2));
        putUInt32(data, 20, nextCommand & 0xFFFFFFFFL);

        receive(data);

        assertDiscarded(credits, first, second);
        connection.handle(new SMB2DecryptedPacketData(data));
        assertDiscarded(credits, first, second);
        receive(frame(response(1), response(2)));
        assertResponse(first, 1);
        assertResponse(second, 2);
    }

    @Test
    public void shouldDiscardCompoundWithMalformedLaterHeader() throws Exception {
        Request first = request(1);
        Request second = request(2);
        int credits = connection.sequenceWindow.available();
        byte[] original = frame(response(1), response(2));
        // An invalid protocol ID, an unknown command, and a truncated final header.
        for (int offset : new int[] {MEMBER_SIZE, MEMBER_SIZE + 12}) {
            byte[] data = original.clone();
            data[offset] = (byte) 0xFF;
            receive(data);
            assertDiscarded(credits, first, second);
        }
        receive(Arrays.copyOf(original, MEMBER_SIZE + 32));
        assertDiscarded(credits, first, second);
    }

    @Test
    public void shouldRejectSingleBadSignatureThenAcceptValidSignedResponse() throws Exception {
        Request outstanding = request(1);
        int credits = connection.sequenceWindow.available();
        byte[] data = frame(response(1));
        data[SMB2PacketHeader.SIGNATURE_OFFSET] ^= 1;
        receive(data);
        assertDiscarded(credits, outstanding);

        receive(frame(response(1)));

        assertResponse(outstanding, 1);
    }

    @Test
    public void shouldDiscardSignedResponseWhoseSessionCannotBeFound() throws Exception {
        Request outstanding = request(1);
        connection.getSessionTable().removeSession(SESSION_ID);
        int credits = connection.sequenceWindow.available();

        receive(frame(response(1)));

        assertDiscarded(credits, outstanding);
    }

    @Test
    public void shouldDiscardUnsignedResponseOnSigningSession() throws Exception {
        Request outstanding = request(1);
        int credits = connection.sequenceWindow.available();

        receive(frame(response(1, SMB2_ECHO, SESSION_ID, false, NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0})));

        assertDiscarded(credits, outstanding);
    }

    @Test
    public void shouldAcceptUnsignedResponseWhenSigningOptional() throws Exception {
        session.getSessionContext().setSigningRequired(false);
        Request outstanding = request(1);

        receive(frame(response(1, SMB2_ECHO, SESSION_ID, false, NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0})));

        assertResponse(outstanding, 1);
    }

    @Test
    public void shouldAcceptInvalidSignatureWhenSigningDisabled() throws Exception {
        client.close();
        SmbConfig config = Utils.configBuilder(new NoOpPacketProcessor())
            .withDialects(SMB2Dialect.SMB_2_1).withSigningEnabled(false).build();
        client = new SMBClient(config);
        connection = client.connect("127.0.0.1");
        session = new Session(connection, config, null, null, null, null, null);
        session.setSessionId(SESSION_ID);
        session.getSessionContext().setSessionKey(new SecretKeySpec(KEY.getEncoded(), KEY.getAlgorithm()));
        connection.getSessionTable().registerSession(SESSION_ID, session);
        Request outstanding = request(1);
        byte[] data = frame(response(1));
        data[SMB2PacketHeader.SIGNATURE_OFFSET] ^= 1;

        receive(data);

        assertResponse(outstanding, 1);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void shouldDiscardFinalAfterSigningRequiredSessionRemoved(boolean signed) throws Exception {
        SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_2_1);
        packet.getHeader().setSessionId(SESSION_ID);
        // The stub transport's immediate unsigned answer is discarded: the session requires signing.
        Future<SMB2Packet> future = connection.send(packet);
        long messageId = packet.getHeader().getMessageId();
        Request request = connection.outstandingRequests.getRequestByMessageId(messageId);
        assertTrue(request.isSigningRequired());
        connection.getSessionTable().removeSession(SESSION_ID);
        int credits = connection.sequenceWindow.available();

        receive(frame(response(messageId, SMB2_ECHO, SESSION_ID, signed, NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0})));

        assertFalse(future.isDone());
        assertDiscarded(credits, request);
    }

    @Test
    public void shouldAcceptUnsignedFinalWhenSessionSigningOptional() throws Exception {
        session.getSessionContext().setSigningRequired(false);
        SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_2_1);
        packet.getHeader().setSessionId(SESSION_ID);

        // The stub transport answers at once with an unsigned response.
        Future<SMB2Packet> future = connection.send(packet);

        long messageId = packet.getHeader().getMessageId();
        assertEquals(messageId, future.get(1, TimeUnit.SECONDS).getHeader().getMessageId());
        assertNull(connection.outstandingRequests.getRequestByMessageId(messageId));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    public void shouldAcceptDecryptedResponsesAndCompounds(int count) throws Exception {
        Request[] requests = new Request[count];
        SMB2Packet[] responses = new SMB2Packet[count];
        for (int i = 0; i < count; i++) {
            requests[i] = request(i + 1);
            responses[i] = response(i + 1);
        }
        byte[] data = frame(responses);
        for (int i = 0; i < count; i++) {
            // Only encryption authenticates these members; their SMB2 signatures are invalid.
            data[i * MEMBER_SIZE + SMB2PacketHeader.SIGNATURE_OFFSET] ^= 1;
        }
        connection.handle(new SMB2DecryptedPacketData(data));

        for (int i = 0; i < count; i++) {
            assertResponse(requests[i], i + 1);
        }
    }

    @Test
    public void shouldAbortWholeDecryptedCompoundWithForeignSession() throws Exception {
        Request first = request(1);
        Request second = request(2, SMB2_ECHO, SESSION_ID + 1);
        int credits = connection.sequenceWindow.available();
        SMB2Packet foreign = response(2, SMB2_ECHO, SESSION_ID + 1, false,
            NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0});

        TransportException violation = assertThrows(TransportException.class,
            () -> connection.handle(new SMB2DecryptedPacketData(frame(response(1), foreign))));

        assertFalse(connection.isConnected());
        assertEquals(credits, connection.sequenceWindow.available());
        assertSame(violation, AbortTestConnection.transportFailure(first.getPromise().future()));
        assertSame(violation, AbortTestConnection.transportFailure(second.getPromise().future()));
    }

    @Test
    public void shouldCaptureRequestCommandAndSessionBeforeHeaderMutation() throws Exception {
        Request outstanding = request(1);
        SMB2Packet packet = (SMB2Packet) outstanding.getPacket();
        packet.getHeader().setMessageType(SMB2_SESSION_SETUP);
        packet.getHeader().setSessionId(0);
        assertEquals(SMB2_ECHO, outstanding.getCommand());
        assertEquals(SESSION_ID, outstanding.getSessionId());
        int credits = connection.sequenceWindow.available();

        receive(frame(response(1, SMB2_SESSION_SETUP, 0, true, NtStatus.STATUS_SUCCESS, new byte[8])));

        assertDiscarded(credits, outstanding);
    }

    @Test
    public void shouldAcceptInitialAndSubsequentSessionSetupResponses() throws Exception {
        Request initial = request(1, SMB2_SESSION_SETUP, 0);
        // StructureSize, SessionFlags, SecurityBufferOffset, SecurityBufferLength.
        byte[] body = new byte[] {9, 0, 0, 0, 72, 0, 0, 0};
        byte[] initialResponse = frame(response(1, SMB2_SESSION_SETUP, SESSION_ID + 1, true,
            NtStatus.STATUS_MORE_PROCESSING_REQUIRED, body));
        initialResponse[SMB2PacketHeader.SIGNATURE_OFFSET] ^= 1;
        receive(initialResponse);
        assertEquals(SESSION_ID + 1, initial.getPromise().future().get(1, TimeUnit.SECONDS).getHeader().getSessionId());

        Request subsequent = request(2, SMB2_SESSION_SETUP, SESSION_ID + 1);
        byte[] finalResponse = frame(response(2, SMB2_SESSION_SETUP, SESSION_ID + 1, true,
            NtStatus.STATUS_SUCCESS, body));
        finalResponse[SMB2PacketHeader.SIGNATURE_OFFSET] ^= 1;
        receive(finalResponse);
        assertResponse(subsequent, 2);
    }

    @ParameterizedTest
    @ValueSource(ints = {24, 44})
    public void shouldConsumeUnsignedBreakNotificationAndProcessFollowingMember(int structureSize) throws Exception {
        Request outstanding = request(1);
        byte[] oplock = new byte[structureSize];
        oplock[0] = (byte) structureSize;
        SMB2Packet notification = response(-1, SMB2_OPLOCK_BREAK, 0, false, NtStatus.STATUS_SUCCESS, oplock);

        receive(frame(notification, response(1)));

        assertResponse(outstanding, 1);
    }

    @Test
    public void shouldKeepReaderAliveAfterCommandMismatchAndMalformedCompounds() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            Session readerSession = new Session(test.connection, SmbConfig.createDefaultConfig(), null, null, null, null, null);
            readerSession.setSessionId(SESSION_ID);
            readerSession.getSessionContext().setSessionKey(new SecretKeySpec(KEY.getEncoded(), KEY.getAlgorithm()));
            readerSession.getSessionContext().setSigningRequired(true);
            test.connection.getSessionTable().registerSession(SESSION_ID, readerSession);
            SMB2Echo firstPacket = new SMB2Echo(SMB2Dialect.SMB_2_1);
            firstPacket.getHeader().setSessionId(SESSION_ID);
            Future<SMB2Packet> first = test.connection.send(firstPacket);
            SMB2Echo secondPacket = new SMB2Echo(SMB2Dialect.SMB_2_1);
            secondPacket.getHeader().setSessionId(SESSION_ID);
            Future<SMB2Packet> second = test.connection.send(secondPacket);
            long firstId = firstPacket.getHeader().getMessageId();
            long secondId = secondPacket.getHeader().getMessageId();
            int credits = test.connection.sequenceWindow.available();
            byte[] mismatch = frame(response(firstId, SMB2_IOCTL, SESSION_ID, true,
                NtStatus.STATUS_INVALID_PARAMETER, new byte[9]));
            byte[] pastEnd = frame(response(firstId), response(secondId));
            putUInt32(pastEnd, 20, pastEnd.length + 8);
            byte[] unaligned = frame(response(firstId), response(secondId));
            putUInt32(unaligned, 20, MEMBER_SIZE + 1);

            test.socket.input.offer(netbios(mismatch));
            test.socket.input.offer(netbios(pastEnd));
            test.socket.input.offer(netbios(unaligned));
            AbortTestConnection.await(() -> test.packetsHandled.get() == 3);
            assertFalse(first.isDone());
            assertFalse(second.isDone());
            assertEquals(credits, test.connection.sequenceWindow.available());
            assertTrue(test.reader.isAlive());
            assertEquals(0, test.errors.get());

            test.socket.input.offer(netbios(frame(response(firstId), response(secondId))));

            assertEquals(firstId, first.get(1, TimeUnit.SECONDS).getHeader().getMessageId());
            assertEquals(secondId, second.get(1, TimeUnit.SECONDS).getHeader().getMessageId());
            assertTrue(test.reader.isAlive());
            assertEquals(0, test.errors.get());
        }
    }

    private byte[] netbios(byte[] data) {
        byte[] result = new byte[data.length + 4];
        result[1] = (byte) (data.length >>> 16);
        result[2] = (byte) (data.length >>> 8);
        result[3] = (byte) data.length;
        System.arraycopy(data, 0, result, 4, data.length);
        return result;
    }

    private Request request(long messageId) throws Exception {
        return request(messageId, SMB2_ECHO, SESSION_ID);
    }

    private Request request(long messageId, SMB2MessageCommandCode command, long sessionId) throws Exception {
        SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_2_1);
        packet.getHeader().setMessageId(messageId);
        packet.getHeader().setMessageType(command);
        packet.getHeader().setSessionId(sessionId);
        Request request = new Request(packet, messageId, UUID.randomUUID());
        connection.outstandingRequests.registerOutstanding(request);
        return request;
    }

    private void receive(byte[] data) throws Exception {
        connection.handle(new SMB2PacketData(data));
    }

    private void assertDiscarded(int credits, Request... requests) {
        assertEquals(credits, connection.sequenceWindow.available(), "discarded frames must grant no credits");
        assertTrue(connection.isConnected());
        for (Request request : requests) {
            assertFalse(request.getPromise().future().isDone(), "discarded frames must complete no future");
            assertSame(request, connection.outstandingRequests.getRequestByMessageId(request.getMessageId()));
        }
    }

    private void assertResponse(Request request, long messageId) throws Exception {
        SMB2Packet packet = request.getPromise().future().get(1, TimeUnit.SECONDS);
        assertEquals(messageId, packet.getHeader().getMessageId());
        assertNull(connection.outstandingRequests.getRequestByMessageId(messageId));
    }
}
