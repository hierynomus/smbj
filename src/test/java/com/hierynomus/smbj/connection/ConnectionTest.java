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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.testing.PacketProcessor;
import com.hierynomus.smbj.testing.StubAuthenticator;
import com.hierynomus.smbj.testing.StubTransportLayerFactory;
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor;
import com.hierynomus.smbj.testing.PacketProcessor.NoOpPacketProcessor;;

public class ConnectionTest {

    private static SmbConfig config(PacketProcessor processor) {
        return SmbConfig.builder()
                .withTransportLayerFactory(new StubTransportLayerFactory<>(new DefaultPacketProcessor().wrap(processor)))
                .withAuthenticators(new StubAuthenticator.Factory()).build();
    }

    @Test
    public void shouldUnregisterServerWhenConnectionClosed() throws Exception {
        SmbConfig config = config(new NoOpPacketProcessor());
        SMBClient client = new SMBClient(config);

        Connection conn = client.connect("foo");
        assertNotNull(client.getServerList().lookup("foo"));

        conn.close();
        assertNull(client.getServerList().lookup("foo"));
    }

    @Test
    public void shouldNotUnregisterServerWhenNotAllConnectionsClosed() throws Exception {
        SmbConfig config = config(new NoOpPacketProcessor());
        SMBClient client = new SMBClient(config);

        Connection conn = client.connect("foo");
        Connection conn2 = client.connect("foo");
        conn.close();

        assertNotNull(client.getServerList().lookup("foo"));

        conn2.close();
        assertNull(client.getServerList().lookup("foo"));
    }

    @Test
    public void shouldConnectToServerWithChangedIdentificationWhenAllConnectionsClosed() throws Exception {
        UUID one = UUID.fromString("ffeeddcc-bbaa-9988-7766-554433221100");
        UUID two = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff");

        final AtomicBoolean sent = new AtomicBoolean(false);
        SmbConfig config = config((SMB2Packet req) -> {
            req = req.getPacket();
            if (!sent.get() && req instanceof SMB2NegotiateRequest) {
                sent.set(true);
                SMB2NegotiateResponse resp = new SMB2NegotiateResponse();
                resp.getHeader().setMessageType(SMB2MessageCommandCode.SMB2_NEGOTIATE);
                resp.getHeader().setStatusCode(NtStatus.STATUS_SUCCESS.getValue());
                resp.setDialect(SMB2Dialect.SMB_2_1);
                resp.setSystemTime(FileTime.now());
                resp.setServerGuid(one);
                return resp;
            }
            return null;
        });

        SMBClient client = new SMBClient(config);

        Connection conn = client.connect("foo");
        Connection conn2 = client.connect("foo");
        assertEquals(one, client.getServerList().lookup("foo").getServerGUID());
        assertEquals(one, conn.getConnectionContext().getServer().getServerGUID());
        assertEquals(one, conn2.getConnectionContext().getServer().getServerGUID());

        conn.close();

        assertNotNull(client.getServerList().lookup("foo"));

        conn2.close();
        assertNull(client.getServerList().lookup("foo"));

        conn = client.connect("foo");
        assertEquals(two, client.getServerList().lookup("foo").getServerGUID());
        assertEquals(two, conn.getConnectionContext().getServer().getServerGUID());
    }
}
