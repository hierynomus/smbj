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
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.mssmb2.messages.negotiate.SMB2EncryptionCapabilities;
import com.hierynomus.mssmb2.messages.negotiate.SMB2NegotiateContext;
import com.hierynomus.mssmb2.messages.negotiate.SMB2PreauthIntegrityCapabilities;
import com.hierynomus.smb.SMBPacketData;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.testing.PacketProcessor;
import com.hierynomus.smbj.testing.PacketProcessor.NoOpPacketProcessor;
import com.hierynomus.smbj.testing.StubAuthenticator;
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor;
import com.hierynomus.smbj.testing.StubTransportLayerFactory;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class ProtocolNegotiatorTest {
    SMBEventBus bus = new SMBEventBus();

    private SmbConfig buildConfig(SmbConfig.Builder builder, PacketProcessor packetProcessor) {
        return builder
                .withTransportLayerFactory(
                        new StubTransportLayerFactory<>(new DefaultPacketProcessor().wrap(packetProcessor)))
                .withAuthenticators(new StubAuthenticator.Factory())
                .build();
    }

    private List<SMB2NegotiateContext> buildNegotateContexts(SMB2Dialect dialect, boolean encryptData)
            throws Exception {
        List<SMB2NegotiateContext> negotiateContexts = new ArrayList<>();
        SmbConfig config = buildConfig(SmbConfig.builder().withDialects(dialect).withEncryptData(encryptData),
                new PacketProcessor() {
                    @Override
                    public SMB2Packet process(SMB2Packet packetData) {
                        SMB2Packet req = packetData.getPacket();
                        if (req instanceof SMB2NegotiateRequest) {
                            SMB2NegotiateRequest negotiateRequest = (SMB2NegotiateRequest) req;
                            negotiateContexts.addAll(negotiateRequest.getNegotiateContextList());
                        }
                        return null;
                    }
                });

        SMBClient client = new SMBClient(config);
        client.connect("localhost");

        return negotiateContexts;
    }

    @Test
    public void shouldNotAddEncryptionCapabilitiesIfEncryptDataIsFalse() throws Exception {
        List<SMB2NegotiateContext> negotiateContexts = buildNegotateContexts(SMB2Dialect.SMB_3_1_1, false);
        assertEquals(1, negotiateContexts.size());
        assertInstanceOf(SMB2PreauthIntegrityCapabilities.class, negotiateContexts.get(0));
    }

    @Test
    public void shouldAddEncryptionCapabilitiesIfEncryptDataIsTrue() throws Exception {
        List<SMB2NegotiateContext> negotiateContexts = buildNegotateContexts(SMB2Dialect.SMB_3_1_1, true);
        assertEquals(2, negotiateContexts.size());
        assertInstanceOf(SMB2PreauthIntegrityCapabilities.class, negotiateContexts.get(0));
        assertInstanceOf(SMB2EncryptionCapabilities.class, negotiateContexts.get(1));
    }

    @ParameterizedTest(name = "Testing dialect {0} for only SMB3x dialects support encryption")
    @EnumSource(value = SMB2Dialect.class)
    public void shouldOnlySupportEncryptionForCompatibleDialects(SMB2Dialect dialect) {
        if (dialect.isSmb3x()) {
            assertDoesNotThrow(() -> buildConfig(SmbConfig.builder().withDialects(dialect).withEncryptData(true),
                new NoOpPacketProcessor()));
        } else {
            assertThrows(IllegalStateException.class, () -> buildConfig(SmbConfig.builder().withDialects(dialect).withEncryptData(true),
                new NoOpPacketProcessor()));
        }
    }

    @ParameterizedTest(name = "Dialect {0} should not contain NegotiateContexts in the SMB2NegotiateRequest")
    @EnumSource(value = SMB2Dialect.class, mode = EnumSource.Mode.EXCLUDE, names = { "SMB_3_1_1" })
    public void shouldNotAddNegotiateContextsForNonSMB311Dialect(SMB2Dialect dialect) throws Exception {
        assertEquals(0, buildNegotateContexts(dialect, false).size());
        if (dialect.isSmb3x()) {
            assertEquals(0, buildNegotateContexts(dialect, true).size());
        }
    }
}
