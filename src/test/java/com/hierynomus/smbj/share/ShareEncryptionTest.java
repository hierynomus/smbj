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
package com.hierynomus.smbj.share;

import static com.hierynomus.mssmb2.SMB2MessageCommandCode.SMB2_CLOSE;
import static com.hierynomus.mssmb2.SMB2MessageCommandCode.SMB2_CREATE;
import static com.hierynomus.mssmb2.SMB2MessageCommandCode.SMB2_FLUSH;
import static com.hierynomus.mssmb2.SMB2MessageCommandCode.SMB2_LOGOFF;
import static com.hierynomus.mssmb2.SMB2MessageCommandCode.SMB2_TREE_DISCONNECT;
import static com.hierynomus.mssmb2.SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR;
import static com.hierynomus.mssmb2.SMB2ShareFlags.SMB2_SHAREFLAG_ENCRYPT_DATA;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toLong;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2GlobalCapability;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.SMB2PacketHeader;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.SMB2ShareFlags;
import com.hierynomus.mssmb2.SMB2TransformHeader;
import com.hierynomus.mssmb2.SMB3EncryptedPacketData;
import com.hierynomus.mssmb2.SMB3EncryptionCipher;
import com.hierynomus.mssmb2.messages.SMB2Close;
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;
import com.hierynomus.mssmb2.messages.SMB2Flush;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup.SMB2SessionFlags;
import com.hierynomus.mssmb2.messages.SMB2TreeConnectRequest;
import com.hierynomus.mssmb2.messages.SMB2TreeConnectResponse;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.PacketEncryptor;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.testing.PacketProcessor;
import com.hierynomus.smbj.testing.Utils;

public class ShareEncryptionTest {
    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void encryptsShareRequestsWhenShareRequiresEncryption(boolean sessionEncrypts) throws Exception {
        RecordingProcessor processor = new RecordingProcessor(SMB2Dialect.SMB_3_0, true, null);
        SmbConfig config = config(processor, true);
        try (SMBClient client = new SMBClient(config)) {
            Connection connection = client.connect("127.0.0.1");
            Session session = authenticate(connection, processor);
            if (!sessionEncrypts) {
                session = spy(session);
                doReturn(false).when(session).shouldEncryptData();
            }
            assertEquals(sessionEncrypts, session.shouldEncryptData());
            assertNotNull(session.getSessionContext().getEncryptionKey());

            DiskShare share = (DiskShare) session.connectShare("encrypted");
            assertTrue(share.getTreeConnect().isEncryptData());
            assertTrue(share.getTreeConnect().getShareFlags().contains(SMB2_SHAREFLAG_ENCRYPT_DATA));
            try (File file = openFile(share)) {
                file.flush();
            }
            share.close();

            PacketEncryptor decryptor = new PacketEncryptor(config.getSecurityProvider());
            decryptor.setCipher(SMB3EncryptionCipher.AES_128_CCM);
            for (SMB2MessageCommandCode command : Arrays.asList(SMB2_CREATE, SMB2_FLUSH, SMB2_CLOSE, SMB2_TREE_DISCONNECT)) {
                assertEquals(1, processor.packets(command).size());
                byte[] bytes = processor.packets(command).get(0);
                assertArrayEquals(SMB2TransformHeader.ENCRYPTED_PROTOCOL_ID, Arrays.copyOf(bytes, 4));
                byte[] plain = decryptor.decrypt(new SMB3EncryptedPacketData(bytes), session.getSessionContext().getEncryptionKey());
                SMB2PacketHeader header = new SMB2PacketData(plain).getHeader();
                assertEquals(command, header.getMessage());
                assertEquals(session.getSessionId(), header.getSessionId());
                assertEquals(share.getTreeConnect().getTreeId(), header.getTreeId());
            }
        }
    }

    @ParameterizedTest
    @MethodSource("unavailableEncryption")
    public void refusesShareUseWhenEncryptionIsUnavailable(SMB2Dialect dialect, boolean clientEncryption,
            boolean serverEncryption, SMB2SessionFlags sessionFlag) throws Exception {
        RecordingProcessor processor = new RecordingProcessor(dialect, serverEncryption, sessionFlag);
        try (SMBClient client = new SMBClient(config(processor, clientEncryption))) {
            Session session = authenticate(client.connect("127.0.0.1"), processor);
            DiskShare share = (DiskShare) session.connectShare("encrypted");
            // TreeConnect.EncryptData describes negotiation; guest/anonymous sessions still lack a key.
            assertEquals(dialect.isSmb3x() && clientEncryption && serverEncryption, share.getTreeConnect().isEncryptData());
            assertTrue(share.getTreeConnect().getShareFlags().contains(SMB2_SHAREFLAG_ENCRYPT_DATA));
            assertNull(session.getSessionContext().getEncryptionKey());

            assertRefused(processor, () -> openFile(share));
            assertRefused(processor, () -> share.list(""));
            assertRefused(processor, () -> share.fileExists("file.txt"));
            assertRefused(processor, () -> share.folderExists("folder"));
            assertRefused(processor, () -> share.ioctl(0, false, new byte[0]));
            int writes = processor.writeCount;
            TransportException exception = assertThrows(TransportException.class, share::close);
            assertEquals("Share " + share.getSmbPath()
                    + " requires encryption but encryption is not available on this connection", exception.getMessage());
            assertEquals(writes, processor.writeCount);
            assertTrue(processor.packets(SMB2_CREATE).isEmpty());
            assertTrue(processor.packets(SMB2_TREE_DISCONNECT).isEmpty());

            // The same connection can still use a share that does not require encryption.
            try (DiskShare plainShare = (DiskShare) session.connectShare("plain")) {
                assertFalse(plainShare.getTreeConnect().isEncryptData());
                assertFalse(plainShare.getTreeConnect().getShareFlags().contains(SMB2_SHAREFLAG_ENCRYPT_DATA));
                try (File ignored = openFile(plainShare)) {
                    assertEquals(1, processor.packets(SMB2_CREATE).size());
                    assertTrue(SMB2PacketHeader.isPacketHeader(Arrays.copyOf(processor.packets(SMB2_CREATE).get(0), 4)));
                }
            }
        }
    }

    @ParameterizedTest
    @MethodSource("unavailableEncryption")
    public void logoffContinuesWhenShareEncryptionIsUnavailable(SMB2Dialect dialect, boolean clientEncryption,
            boolean serverEncryption, SMB2SessionFlags sessionFlag) throws Exception {
        RecordingProcessor processor = new RecordingProcessor(dialect, serverEncryption, sessionFlag);
        try (SMBClient client = new SMBClient(config(processor, clientEncryption))) {
            Session session = authenticate(client.connect("127.0.0.1"), processor);
            Share encryptedShare = session.connectShare("encrypted");
            Share plainShare = session.connectShare("plain");

            session.logoff();

            assertFalse(encryptedShare.isConnected());
            assertFalse(plainShare.isConnected());
            assertEquals(1, processor.packets(SMB2_TREE_DISCONNECT).size());
            SMB2PacketHeader disconnect = new SMB2PacketData(processor.packets(SMB2_TREE_DISCONNECT).get(0)).getHeader();
            assertEquals(plainShare.getTreeConnect().getTreeId(), disconnect.getTreeId());
            assertEquals(session.getSessionId(), disconnect.getSessionId());
            assertEquals(1, processor.packets(SMB2_LOGOFF).size());
            SMB2PacketHeader logoff = new SMB2PacketData(processor.packets(SMB2_LOGOFF).get(0)).getHeader();
            assertEquals(session.getSessionId(), logoff.getSessionId());
        }
    }

    private static Stream<Arguments> unavailableEncryption() {
        return Stream.of(
                Arguments.of(SMB2Dialect.SMB_3_0, false, true, null),
                Arguments.of(SMB2Dialect.SMB_3_0, true, false, null),
                Arguments.of(SMB2Dialect.SMB_2_1, false, false, null),
                Arguments.of(SMB2Dialect.SMB_3_0, true, true, SMB2SessionFlags.SMB2_SESSION_FLAG_IS_GUEST),
                Arguments.of(SMB2Dialect.SMB_3_0, true, true, SMB2SessionFlags.SMB2_SESSION_FLAG_IS_NULL));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void preservesSessionPolicyForSharesWithoutEncryptionFlag(boolean sessionEncrypts) throws Exception {
        RecordingProcessor processor = new RecordingProcessor(SMB2Dialect.SMB_3_0, true, null);
        try (SMBClient client = new SMBClient(config(processor, true))) {
            Session session = authenticate(client.connect("127.0.0.1"), processor);
            if (!sessionEncrypts) {
                session = spy(session);
                doReturn(false).when(session).shouldEncryptData();
            }
            try (DiskShare share = (DiskShare) session.connectShare("plain")) {
                assertFalse(share.getTreeConnect().isEncryptData());
                try (File ignored = openFile(share)) {
                    assertEquals(1, processor.packets(SMB2_CREATE).size());
                    byte[] protocolId = Arrays.copyOf(processor.packets(SMB2_CREATE).get(0), 4);
                    if (sessionEncrypts) {
                        assertArrayEquals(SMB2TransformHeader.ENCRYPTED_PROTOCOL_ID, protocolId);
                    } else {
                        assertTrue(SMB2PacketHeader.isPacketHeader(protocolId));
                    }
                }
            }
        }
    }

    @Test
    public void copiesShareFlagsFromTreeConnectResponse() throws Exception {
        RecordingProcessor processor = new RecordingProcessor(SMB2Dialect.SMB_2_1, false, null);
        try (SMBClient client = new SMBClient(config(processor, false))) {
            Session session = authenticate(client.connect("127.0.0.1"), processor);
            DiskShare share = (DiskShare) session.connectShare("encrypted");
            TreeConnect tree = share.getTreeConnect();
            Set<SMB2ShareFlags> expected = EnumSet.copyOf(processor.shareFlags);
            assertEquals(expected, tree.getShareFlags());
            assertThrows(UnsupportedOperationException.class, () -> tree.getShareFlags().clear());
            processor.shareFlags.clear();
            assertEquals(expected, tree.getShareFlags());
            assertFalse(tree.isEncryptData());
            assertRefused(processor, () -> openFile(share));
        }
    }

    private static SmbConfig config(RecordingProcessor processor, boolean clientEncryption) {
        return Utils.configBuilder(processor)
                .withDialects(processor.dialect)
                .withEncryptData(clientEncryption)
                .withSecurityProvider(new BCSecurityProvider())
                .withDirectoryLeasingEnabled(false)
                .withTimeout(1, TimeUnit.SECONDS)
                .build();
    }

    private static Session authenticate(Connection connection, RecordingProcessor processor) {
        Session session = connection.authenticate(new AuthenticationContext("user", new char[0], "domain"));
        processor.session = session;
        return session;
    }

    private static File openFile(DiskShare share) {
        return share.openFile("file.txt", EnumSet.of(AccessMask.GENERIC_READ),
                EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL,
                SMB2CreateDisposition.FILE_OPEN, null);
    }

    private static void assertRefused(RecordingProcessor processor, Executable action) {
        int writes = processor.writeCount;
        SMBRuntimeException exception = assertThrows(SMBRuntimeException.class, action);
        assertTrue(exception.getMessage().contains("encrypted"));
        assertTrue(exception.getMessage().contains("requires encryption but encryption is not available on this connection"));
        assertEquals(writes, processor.writeCount);
    }

    private static class RecordingProcessor implements PacketProcessor {
        private final PacketProcessor defaults = new PacketProcessor.DefaultPacketProcessor();
        private final SMB2Dialect dialect;
        private final boolean serverEncryption;
        private final SMB2SessionFlags sessionFlag;
        private final Set<SMB2ShareFlags> shareFlags = EnumSet.of(SMB2_SHAREFLAG_ENCRYPT_DATA,
                SMB2ShareFlags.SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM);
        private final Map<SMB2MessageCommandCode, List<byte[]>> packets = new EnumMap<>(SMB2MessageCommandCode.class);
        private final PacketEncryptor encryptor = new PacketEncryptor(new BCSecurityProvider());
        private Session session;
        private int writeCount;

        private RecordingProcessor(SMB2Dialect dialect, boolean serverEncryption, SMB2SessionFlags sessionFlag) {
            this.dialect = dialect;
            this.serverEncryption = serverEncryption;
            this.sessionFlag = sessionFlag;
            encryptor.setCipher(SMB3EncryptionCipher.AES_128_CCM);
        }

        private List<byte[]> packets(SMB2MessageCommandCode command) {
            List<byte[]> result = packets.get(command);
            return result == null ? Collections.emptyList() : result;
        }

        @Override
        public SMB2Packet process(SMB2Packet packet) {
            writeCount++;
            SMB2Packet request = packet.getPacket();
            SMB2MessageCommandCode command = request.getHeader().getMessage();
            SMBBuffer buffer = new SMBBuffer();
            packet.write(buffer);
            packets.computeIfAbsent(command, key -> new ArrayList<>()).add(buffer.getCompactData());

            SMB2Packet response;
            if (command == SMB2_CREATE) {
                SMB2CreateResponse create = new SMB2CreateResponse();
                create.setFileAttributes(EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL));
                create.setFileId(new SMB2FileId(new byte[8], new byte[8]));
                response = create;
            } else if (command == SMB2_CLOSE) {
                response = new SMB2Close();
            } else if (command == SMB2_FLUSH) {
                response = new SMB2Flush();
            } else {
                response = defaults.process(request);
                if (response instanceof SMB2NegotiateResponse) {
                    SMB2NegotiateResponse negotiate = (SMB2NegotiateResponse) response;
                    negotiate.setDialect(dialect);
                    negotiate.setSystemTime(FileTime.ofEpochMillis(0));
                    if (serverEncryption) {
                        negotiate.getCapabilities().add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_ENCRYPTION);
                    }
                } else if (response instanceof SMB2SessionSetup && sessionFlag != null) {
                    ((SMB2SessionSetup) response).setSessionFlags(EnumSet.of(sessionFlag));
                } else if (response instanceof SMB2TreeConnectResponse) {
                    boolean encrypted = "encrypted".equals(((SMB2TreeConnectRequest) request).getSmbPath().getShareName());
                    ((SMB2TreeConnectResponse) response).setShareFlags(encrypted ? shareFlags : Collections.emptySet());
                    response.getHeader().setTreeId(encrypted ? 1 : 2);
                }
            }
            response.getHeader().setMessageType(command);
            if (packet instanceof PacketEncryptor.EncryptedPacketWrapper) {
                assertNotNull(session.getSessionContext().getDecryptionKey());
                return encryptor.encrypt(wireResponse(response), session.getSessionContext().getDecryptionKey());
            }
            return response;
        }

        private SMB2Packet wireResponse(final SMB2Packet response) {
            // Most response classes only implement reading, so supply their wire representation here.
            return new SMB2Packet() {
                @Override
                public SMB2PacketHeader getHeader() {
                    return response.getHeader();
                }

                @Override
                public void write(SMBBuffer buffer) {
                    SMBBuffer plain = new SMBBuffer();
                    SMB2PacketHeader header = getHeader();
                    header.setDialect(dialect);
                    header.setFlag(SMB2_FLAGS_SERVER_TO_REDIR);
                    header.writeTo(plain);
                    writeResponseBody(response, plain);
                    byte[] data = plain.getCompactData();
                    // The production header writer emits request status and credit fields.
                    for (int i = 0; i < 4; i++) {
                        data[8 + i] = (byte) (header.getStatusCode() >>> (8 * i));
                    }
                    data[14] = (byte) header.getCreditResponse();
                    data[15] = (byte) (header.getCreditResponse() >>> 8);
                    buffer.putRawBytes(data);
                }
            };
        }

        private void writeResponseBody(SMB2Packet response, SMBBuffer buffer) {
            switch (response.getHeader().getMessage()) {
                case SMB2_TREE_CONNECT:
                    SMB2TreeConnectResponse tree = (SMB2TreeConnectResponse) response;
                    buffer.putUInt16(16); // StructureSize
                    buffer.putByte((byte) 1); // Disk share
                    buffer.putReserved(1);
                    buffer.putUInt32(toLong(tree.getShareFlags()));
                    buffer.putUInt32(toLong(tree.getCapabilities()));
                    buffer.putUInt32(0); // MaximalAccess
                    break;
                case SMB2_CREATE:
                    SMB2CreateResponse create = (SMB2CreateResponse) response;
                    buffer.putUInt16(89); // StructureSize
                    buffer.putReserved(2); // OplockLevel and Flags
                    buffer.putUInt32(1); // FILE_OPENED
                    buffer.putReserved(48); // Timestamps, AllocationSize and EndOfFile
                    buffer.putUInt32(toLong(create.getFileAttributes()));
                    buffer.putReserved4();
                    create.getFileId().write(buffer);
                    buffer.putReserved(8); // CreateContextsOffset and CreateContextsLength
                    break;
                case SMB2_CLOSE:
                    buffer.putUInt16(60); // StructureSize
                    buffer.putReserved(58);
                    break;
                case SMB2_FLUSH:
                case SMB2_TREE_DISCONNECT:
                case SMB2_LOGOFF:
                    buffer.putUInt16(4); // StructureSize
                    buffer.putReserved2();
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported encrypted response " + response);
            }
        }
    }
}
