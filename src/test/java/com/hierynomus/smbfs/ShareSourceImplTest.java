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
package com.hierynomus.smbfs;

import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ShareSourceImplTest {

    @Mock
    private SMBClient smbClient;

    @Mock
    private Connection connection;

    @Mock
    private Session session;

    @Mock
    private DiskShare diskShare;

    @Test
    void closeShutsDownClient() throws Exception {
        ShareSourceImpl source = new ShareSourceImpl(smbClient, "host", 445, AuthenticationContext.anonymous());

        source.close();

        verify(smbClient).close();
    }

    @Test
    void rejectsOpenAfterClose() throws Exception {
        ShareSourceImpl source = new ShareSourceImpl(smbClient, "host", 445, AuthenticationContext.anonymous());

        source.close();

        assertThrows(IllegalStateException.class, () -> source.getShare("share"));
    }

    @Test
    void reusesTheSameConnectionSessionAndShare() throws Exception {
        when(smbClient.connect(anyString(), anyInt())).thenReturn(connection);
        when(connection.authenticate(any())).thenReturn(session);
        when(session.connectShare("share")).thenReturn(diskShare);
        when(diskShare.isConnected()).thenReturn(true);

        ShareSourceImpl source = new ShareSourceImpl(smbClient, "host", 445, AuthenticationContext.anonymous());

        DiskShare first = source.getShare("share");
        DiskShare second = source.getShare("share");

        assertSame(diskShare, first);
        assertSame(diskShare, second);
        verify(smbClient).connect("host", 445);
        verify(connection).authenticate(any());
        verify(session).connectShare("share");
    }

    @Test
    void reconnectsOnceAfterTransportFailure() throws Exception {
        DiskShare reconnectedShare = mock(DiskShare.class);
        Connection secondConnection = mock(Connection.class);
        Session secondSession = mock(Session.class);

        when(smbClient.connect(anyString(), anyInt())).thenReturn(connection, secondConnection);
        when(connection.authenticate(any())).thenReturn(session);
        when(secondConnection.authenticate(any())).thenReturn(secondSession);
        when(session.connectShare("share"))
            .thenThrow(new SMBRuntimeException(new TransportException("connection reset")));
        when(secondSession.connectShare("share")).thenReturn(reconnectedShare);
        when(session.getConnection()).thenReturn(connection);

        ShareSourceImpl source = new ShareSourceImpl(smbClient, "host", 445, AuthenticationContext.anonymous());

        DiskShare result = source.getShare("share");

        assertSame(reconnectedShare, result);
        verify(smbClient, org.mockito.Mockito.times(2)).connect("host", 445);
    }

    private static <T> T mock(Class<T> type) {
        return org.mockito.Mockito.mock(type);
    }
}
