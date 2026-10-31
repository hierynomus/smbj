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
import com.hierynomus.mssmb2.SMB2MessageFlag;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.commons.concurrent.Promise;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import javax.net.SocketFactory;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static com.hierynomus.smbj.connection.AbortTestConnection.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Timeout(15)
public class ConnectionAbortTest {
    @Test
    public void abortWakesFourCreditStarvedSenders() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            test.connection.sequenceWindow.get(test.connection.sequenceWindow.available());
            Thread[] threads = new Thread[4];
            CountDownLatch started = new CountDownLatch(4);
            List<FutureTask<TransportException>> senders = new ArrayList<>();
            for (int i = 0; i < threads.length; i++) {
                final int index = i;
                senders.add(task(() -> {
                    threads[index] = Thread.currentThread();
                    started.countDown();
                    return assertThrows(TransportException.class, () -> test.connection.send(echo()));
                }));
            }
            assertTrue(started.await(3, TimeUnit.SECONDS));
            await(() -> {
                for (Thread thread : threads) {
                    if (thread.getState() != Thread.State.WAITING && thread.getState() != Thread.State.TIMED_WAITING) {
                        return false;
                    }
                }
                return true;
            });

            long start = System.nanoTime();
            abort(test).get(1, TimeUnit.SECONDS);
            for (FutureTask<TransportException> sender : senders) {
                assertNotNull(sender.get(1, TimeUnit.SECONDS));
            }
            assertPrompt(start);
            assertLaterSendFails(test);
            test.assertNoOutstandingRequests();
        }
    }

    @Test
    public void abortReleasesStalledSocketWrite() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            test.socket.output.stall = true;
            FutureTask<TransportException> writer = task(() ->
                assertThrows(TransportException.class, () -> test.connection.send(echo())));
            await(() -> test.socket.output.blocked);

            long start = System.nanoTime();
            abort(test).get(1, TimeUnit.SECONDS);
            assertNotNull(writer.get(1, TimeUnit.SECONDS));
            assertPrompt(start);
            assertEquals(1, test.socket.closeCalls.get());
            test.assertNoOutstandingRequests();
        }
    }

    @Test
    public void abortStopsReaderBlockedInPartialHeader() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            test.socket.input.offer(new byte[] {0, 0});
            await(() -> test.socket.input.consumed == 2 && test.socket.input.blocked);

            long start = System.nanoTime();
            abort(test).get(1, TimeUnit.SECONDS);
            test.reader.join(1000);
            assertFalse(test.reader.isAlive());
            assertPrompt(start);
            assertEquals(0, test.errors.get());
        }
    }

    @Test
    public void abortFailsResponseWaitersIncludingPendingAsyncRequest() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            SMB2Echo first = echo();
            Future<SMB2Packet> response = test.connection.send(first);
            SMB2Echo second = echo();
            Future<SMB2Packet> asyncResponse = test.connection.send(second);
            SMB2Packet pending = ResponseTestPackets.response(second.getHeader().getMessageId(),
                second.getHeader().getMessage(), 0, false, NtStatus.STATUS_PENDING, new byte[] {9, 0, 0, 0, 0, 0, 0, 0});
            pending.getHeader().setMessageId(second.getHeader().getMessageId());
            pending.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND);
            pending.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR);
            pending.getHeader().setStatusCode(NtStatus.STATUS_PENDING.getValue());
            pending.getHeader().setAsyncId(123);
            test.socket.input.offer(frame(pending));
            Request asyncRequest = test.connection.outstandingRequests.getRequestByMessageId(second.getHeader().getMessageId());
            await(() -> test.packetsHandled.get() == 1);
            assertEquals(123, asyncRequest.getAsyncId());
            FutureTask<Throwable> waiter = task(() -> transportFailure(response));
            FutureTask<Throwable> asyncWaiter = task(() -> transportFailure(asyncResponse));
            Request firstRequest = test.connection.outstandingRequests.getRequestByMessageId(first.getHeader().getMessageId());
            await(() -> firstRequest.getPromise().hasWaiters() && asyncRequest.getPromise().hasWaiters());

            long start = System.nanoTime();
            abort(test).get(1, TimeUnit.SECONDS);
            assertNotNull(waiter.get(1, TimeUnit.SECONDS));
            assertNotNull(asyncWaiter.get(1, TimeUnit.SECONDS));
            assertPrompt(start);
            test.assertNoOutstandingRequests();
        }
    }

    @Test
    public void receiverRuntimeFailureAbortsSharedConnectionExactlyOnceWithoutLogoff() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            test.connection.lease();
            Session session = mock(Session.class);
            test.connection.getSessionTable().registerSession(1L, session);
            SMB2Echo request = echo();
            Future<SMB2Packet> response = test.connection.send(request);
            RuntimeException failure = new IllegalStateException("decrypt failed");
            test.receiverFailure = failure;

            long start = System.nanoTime();
            test.respond(request);
            Throwable cause = transportFailure(response);
            assertSame(failure, cause.getCause());
            test.reader.join(1000);
            assertFalse(test.reader.isAlive());
            assertPrompt(start);
            assertEquals(1, test.errors.get());
            assertEquals(1, test.socket.closeCalls.get());
            assertEquals(1, test.closedEvents.get());
            verify(session, never()).close();
            assertLaterSendFails(test);
            test.assertNoOutstandingRequests();
        }
    }

    @Test
    public void decoderErrorAlsoAbortsAndReportsOnlyOnce() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            SMB2Echo request = echo();
            Future<SMB2Packet> response = test.connection.send(request);
            Error failure = new AssertionError("decoder failed");
            test.decoderFailure = failure;

            long start = System.nanoTime();
            test.respond(request);
            assertSame(failure, transportFailure(response).getCause());
            test.reader.join(1000);
            assertFalse(test.reader.isAlive());
            assertPrompt(start);
            assertEquals(1, test.errors.get());
            test.assertNoOutstandingRequests();
        }
    }

    @Test
    public void closingSocketUnderneathFailsRequestsAndCreditWaiters() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            Future<SMB2Packet> response = test.connection.send(echo());
            test.connection.sequenceWindow.get(test.connection.sequenceWindow.available());
            AtomicReference<Thread> sending = new AtomicReference<>();
            FutureTask<TransportException> sender = task(() -> {
                sending.set(Thread.currentThread());
                return assertThrows(TransportException.class, () -> test.connection.send(echo()));
            });
            await(() -> sending.get() != null && sending.get().getState() == Thread.State.TIMED_WAITING);
            await(() -> test.socket.input.blocked);

            long start = System.nanoTime();
            test.socket.close();
            transportFailure(response);
            sender.get(1, TimeUnit.SECONDS);
            test.reader.join(1000);
            assertFalse(test.reader.isAlive());
            assertPrompt(start);
            assertEquals(1, test.errors.get());
            assertEquals(1, test.socket.closeCalls.get());
            assertLaterSendFails(test);
            test.assertNoOutstandingRequests();
        }
    }

    @Test
    public void abortDoesNotAffectAnotherConnectionOfSameClient() throws Exception {
        try (ClientContext client = new ClientContext();
             AbortTestConnection first = new AbortTestConnection(client);
             AbortTestConnection second = new AbortTestConnection(client, "127.0.0.2")) {
            SMB2Echo request = echo();
            Future<SMB2Packet> response = second.connection.send(request);
            long start = System.nanoTime();
            FutureTask<Void> aborted = abort(first);
            second.respond(request);
            assertEquals(request.getHeader().getMessageId(), response.get(1, TimeUnit.SECONDS).getHeader().getMessageId());
            aborted.get(1, TimeUnit.SECONDS);
            request = echo();
            response = second.connection.send(request);
            second.respond(request);
            response.get(1, TimeUnit.SECONDS);
            assertPrompt(start);
            assertTrue(second.connection.isConnected());
            assertEquals(0, second.errors.get());
            assertEquals(0, second.closedEvents.get());
        }
    }

    @Test
    public void concurrentAndRepeatedAbortClosesAndPublishesOnce() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            Future<SMB2Packet> response = test.connection.send(echo());
            CountDownLatch startClose = new CountDownLatch(1);
            FutureTask<Void> first = task(() -> {
                assertTrue(startClose.await(3, TimeUnit.SECONDS));
                test.connection.close(true);
                return null;
            });
            FutureTask<Void> second = task(() -> {
                assertTrue(startClose.await(3, TimeUnit.SECONDS));
                test.connection.close(true);
                return null;
            });

            long start = System.nanoTime();
            startClose.countDown();
            first.get(1, TimeUnit.SECONDS);
            second.get(1, TimeUnit.SECONDS);
            Throwable failure = transportFailure(response);
            abort(test).get(1, TimeUnit.SECONDS);
            test.connection.handleError(new TransportException("second error"));
            assertSame(failure, transportFailure(response));
            assertPrompt(start);
            assertEquals(1, test.socket.closeCalls.get());
            assertEquals(1, test.closedEvents.get());
            test.assertNoOutstandingRequests();
        }
    }

    @Test
    public void requestRegisteredAfterAbortIsFailedAndRejected() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            CountDownLatch registering = new CountDownLatch(1);
            CountDownLatch resume = new CountDownLatch(1);
            AtomicReference<Request> registered = new AtomicReference<>();
            test.connection.outstandingRequests = new OutstandingRequests() {
                @Override
                void registerOutstanding(Request request) throws TransportException {
                    registered.set(request);
                    registering.countDown();
                    try {
                        if (!resume.await(3, TimeUnit.SECONDS)) {
                            throw new TransportException("Test registration timed out");
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new TransportException(e);
                    }
                    super.registerOutstanding(request);
                }
            };
            FutureTask<TransportException> sender = task(() ->
                assertThrows(TransportException.class, () -> test.connection.send(echo())));
            assertTrue(registering.await(3, TimeUnit.SECONDS));

            long start = System.nanoTime();
            abort(test).get(1, TimeUnit.SECONDS);
            resume.countDown();
            sender.get(1, TimeUnit.SECONDS);
            transportFailure(registered.get().getFuture(null));
            assertPrompt(start);
            test.assertNoOutstandingRequests();
        }
    }

    @Test
    public void abortBeforeSocketOpensDoesNotLeaveTransportConnected() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            test.connection.transport.disconnect();
            TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
            AtomicBoolean connected = new AtomicBoolean();
            CountDownLatch connecting = new CountDownLatch(1);
            CountDownLatch resume = new CountDownLatch(1);
            when(transport.isConnected()).thenAnswer(invocation -> connected.get());
            doAnswer(invocation -> {
                connecting.countDown();
                assertTrue(resume.await(3, TimeUnit.SECONDS));
                connected.set(true);
                return null;
            }).when(transport).connect(any());
            doAnswer(invocation -> {
                connected.set(false);
                return null;
            }).when(transport).disconnect();
            test.connection.transport = transport;
            FutureTask<TransportException> connector = task(() -> assertThrows(TransportException.class,
                () -> test.connection.connect("127.0.0.1", 445)));
            assertTrue(connecting.await(3, TimeUnit.SECONDS));

            long start = System.nanoTime();
            abort(test).get(1, TimeUnit.SECONDS);
            resume.countDown();
            assertNotNull(connector.get(1, TimeUnit.SECONDS));
            assertFalse(connected.get());
            assertEquals(1, test.closedEvents.get());
            verify(transport, never()).write(any());
            assertPrompt(start);
        }
    }

    @Test
    public void abortWhileSocketFactoryIsBlockedClosesLateSocketWithoutStartingReader() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            DirectTcpTransport<?, ?> transport = (DirectTcpTransport<?, ?>) test.connection.transport;
            transport.disconnect();
            test.reader.join(3000);
            assertFalse(test.reader.isAlive());
            Field readerField = DirectTcpTransport.class.getDeclaredField("packetReaderThread");
            readerField.setAccessible(true);
            Object reader = readerField.get(transport);
            TestSocket socket = new TestSocket();
            SocketFactory socketFactory = mock(SocketFactory.class);
            CountDownLatch creating = new CountDownLatch(1);
            CountDownLatch resume = new CountDownLatch(1);
            when(socketFactory.createSocket(anyString(), anyInt())).thenAnswer(invocation -> {
                creating.countDown();
                assertTrue(resume.await(3, TimeUnit.SECONDS));
                return socket;
            });
            transport.setSocketFactory(socketFactory);
            FutureTask<TransportException> connector = task(() -> assertThrows(TransportException.class,
                () -> test.connection.connect("127.0.0.1", 445)));
            try {
                assertTrue(creating.await(3, TimeUnit.SECONDS));

                long start = System.nanoTime();
                abort(test).get(1, TimeUnit.SECONDS);
                assertPrompt(start);
                assertFalse(connector.isDone());
            } finally {
                resume.countDown();
            }

            assertNotNull(connector.get(3, TimeUnit.SECONDS));
            assertTrue(socket.isClosed());
            assertEquals(1, socket.closeCalls.get());
            assertFalse(transport.isConnected());
            assertSame(reader, readerField.get(transport));
            assertFalse(test.reader.isAlive());
            assertEquals(1, test.closedEvents.get());
        }
    }

    @Test
    public void outstandingRequestsDeliverFailureOnlyOnce() throws Exception {
        OutstandingRequests requests = new OutstandingRequests();
        Request request = spy(new Request(echo(), 0, UUID.randomUUID()));
        Promise<SMB2Packet, SMBRuntimeException> promise = spy(request.getPromise());
        doReturn(promise).when(request).getPromise();
        requests.registerOutstanding(request);
        TransportException failure = new TransportException("first failure");

        requests.handleError(failure);
        requests.handleError(new TransportException("second failure"));

        verify(promise, times(1)).deliverError(failure);
        verify(promise, times(1)).deliverError(any(Throwable.class));
        assertSame(failure, transportFailure(promise.future()));
        assertFalse(requests.isOutstanding(0L));
        assertNull(requests.getRequestByCancelId(request.getCancelId()));
        Request late = new Request(echo(), 1, UUID.randomUUID());
        assertSame(failure, assertThrows(TransportException.class, () -> requests.registerOutstanding(late)));
        assertSame(failure, transportFailure(late.getFuture(null)));
    }

    @Test
    public void abortWakesAllWaitersOnSequenceWindow() throws Exception {
        SequenceWindow window = new SequenceWindow();
        window.get();
        Thread[] threads = new Thread[4];
        CountDownLatch started = new CountDownLatch(4);
        List<FutureTask<TransportException>> waiters = new ArrayList<>();
        for (int i = 0; i < threads.length; i++) {
            final int index = i;
            waiters.add(task(() -> {
                threads[index] = Thread.currentThread();
                started.countDown();
                return assertThrows(TransportException.class, () -> window.get());
            }));
        }
        assertTrue(started.await(3, TimeUnit.SECONDS));
        await(() -> {
            for (Thread thread : threads) {
                if (thread.getState() != Thread.State.TIMED_WAITING) {
                    return false;
                }
            }
            return true;
        });
        TransportException failure = new TransportException("aborted");
        long start = System.nanoTime();
        window.handleError(failure);
        for (FutureTask<TransportException> waiter : waiters) {
            assertSame(failure, waiter.get(1, TimeUnit.SECONDS));
        }
        assertPrompt(start);
        window.creditsGranted(10);
        assertSame(failure, assertThrows(TransportException.class, () -> window.get()));
    }

    @Test
    public void healthyGracefulCloseStillReleasesPoolAndClosesSessions() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            Session session = mock(Session.class);
            test.connection.getSessionTable().registerSession(1L, session);
            test.connection.lease();
            test.connection.close(false);
            assertTrue(test.connection.isConnected());
            verify(session, never()).close();
            assertEquals(0, test.closedEvents.get());
            task(() -> {
                test.connection.close();
                return null;
            }).get(1, TimeUnit.SECONDS);
            verify(session).close();
            assertEquals(1, test.closedEvents.get());
        }
    }

    @Test
    public void abortStopsLeaseWorkerStalledInSocketWrite() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            Field executorField = LeaseManager.class.getDeclaredField("breakExecutor");
            executorField.setAccessible(true);
            ExecutorService executor = (ExecutorService) executorField.get(test.connection.getLeaseManager());
            AtomicReference<Thread> worker = new AtomicReference<>();
            test.socket.output.stall = true;
            Future<TransportException> writer = executor.submit(() -> {
                worker.set(Thread.currentThread());
                return assertThrows(TransportException.class, () -> test.connection.send(echo()));
            });
            await(() -> test.socket.output.blocked);

            long start = System.nanoTime();
            abort(test).get(1, TimeUnit.SECONDS);
            assertNotNull(writer.get(1, TimeUnit.SECONDS));
            worker.get().join(1000);
            assertFalse(worker.get().isAlive());
            assertTrue(executor.isTerminated());
            assertPrompt(start);
            test.assertNoOutstandingRequests();
        }
    }

    @Test
    @Timeout(60)
    public void thousandConnectAbortCyclesLeaveNoReadersLeaseThreadsOrRequests() throws Exception {
        int before = connectionThreadCount();
        Field executorField = LeaseManager.class.getDeclaredField("breakExecutor");
        executorField.setAccessible(true);
        try (ClientContext client = new ClientContext()) {
            for (int i = 0; i < 1000; i++) {
                try (AbortTestConnection test = new AbortTestConnection(client)) {
                    ExecutorService executor = (ExecutorService) executorField.get(test.connection.getLeaseManager());
                    Thread leaseThread = executor.submit(() -> Thread.currentThread()).get(3, TimeUnit.SECONDS);
                    Future<SMB2Packet> response = test.connection.send(echo());
                    long start = System.nanoTime();
                    abort(test).get(1, TimeUnit.SECONDS);
                    transportFailure(response);
                    test.reader.join(1000);
                    leaseThread.join(1000);
                    assertFalse(test.reader.isAlive());
                    assertFalse(leaseThread.isAlive());
                    assertPrompt(start);
                    test.assertNoOutstandingRequests();
                }
            }
        }
        await(() -> connectionThreadCount() <= before);
        assertTrue(connectionThreadCount() <= before);
    }

    private static FutureTask<Void> abort(AbortTestConnection test) {
        return task(() -> {
            test.connection.close(true);
            return null;
        });
    }

    private static void assertLaterSendFails(AbortTestConnection test) throws Exception {
        long start = System.nanoTime();
        task(() -> assertThrows(TransportException.class, () -> test.connection.send(echo()))).get(1, TimeUnit.SECONDS);
        assertPrompt(start);
    }

    private static int connectionThreadCount() {
        int count = 0;
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (thread.isAlive() && (thread.getName().startsWith("Packet Reader for ")
                || thread.getName().equals("smbj-lease-break"))) {
                count++;
            }
        }
        return count;
    }
}
