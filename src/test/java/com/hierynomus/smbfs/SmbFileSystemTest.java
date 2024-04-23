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

import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.inOrder;

@ExtendWith(MockitoExtension.class)
class SmbFileSystemTest {

    @Mock
    private SmbFileSystemProvider provider;

    @Mock
    private Connection connection;

    @Mock
    private Session session;

    private SmbFileSystem fileSystem;

    @BeforeEach
    void setUp() {
        fileSystem = new SmbFileSystem(provider, connection, session, "theShare");
    }

    @Test
    void closesAndRemovesFromProvider() throws Exception {
        fileSystem.close();

        assertFalse(fileSystem.isOpen());

        InOrder o = inOrder(provider, connection, session);
        o.verify(provider).removeFileSystem(fileSystem);
        o.verify(session).close();
        o.verify(connection).close();
        o.verifyNoMoreInteractions();
    }
}
