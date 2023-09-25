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
package com.hierynomus.smbj.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.EnumSet;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.messages.SMB2CreateRequest;
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;
import com.hierynomus.protocol.commons.concurrent.Promise;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.NegotiatedProtocol;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.paths.PathResolver;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.smbj.share.TreeConnect;

public class SessionTest {
    @Test
    public void shareNameCannotContainBackslashes() {
        SmbConfig cfg = SmbConfig.createDefaultConfig();
        Connection c = mock(Connection.class);
        Session s = new Session(c, cfg, null, mock(SMBEventBus.class), null, null, null);
        Exception ex = assertThrows(IllegalArgumentException.class, () -> s.connectShare("foo\\bar"));
        assertThat(ex.getMessage()).contains("foo\\bar");
    }

    @Test
    public void shouldUseOpenIfIfNoCreateDispositionProvided() throws Exception {
        SmbConfig cfg = SmbConfig.createDefaultConfig();
        Session s = mock(Session.class);
        TreeConnect tc = mock(TreeConnect.class);
        when(tc.getSession()).thenReturn(s);
        when(tc.getConfig()).thenReturn(cfg);
        when(tc.getNegotiatedProtocol())
                .thenReturn(new NegotiatedProtocol(SMB2Dialect.SMB_2_0_2, 1024, 1024, 1024, true));
        DiskShare share = new DiskShare(new SmbPath("localhost", "public"), tc, PathResolver.LOCAL);
        when(s.send(isA(SMB2CreateRequest.class))).thenAnswer(new Answer<Future<SMB2CreateResponse>>() {
            @Override
            public Future<SMB2CreateResponse> answer(InvocationOnMock invocation) throws Throwable {
                SMB2CreateRequest req = (SMB2CreateRequest) invocation.getArguments()[0];
                assertThat(req.getCreateDisposition()).isEqualTo(SMB2CreateDisposition.FILE_OPEN_IF);
                Promise<SMB2CreateResponse, TransportException> p = new Promise<>("foo", TransportException.Wrapper);
                SMB2CreateResponse resp = new SMB2CreateResponse();
                resp.setFileAttributes(EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL));
                p.deliver(resp);
                return p.future();
            }
        });
        File f = share.openFile("foo", null, null, SMB2ShareAccess.ALL, null, null);

    }
}
