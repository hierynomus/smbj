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

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.util.HashMap;
import java.util.Map;

import static com.hierynomus.smbfs.SmbFileSystemProvider.DOMAIN_PROPERTY;
import static com.hierynomus.smbfs.SmbFileSystemProvider.PASSWORD_PROPERTY;
import static com.hierynomus.smbfs.SmbFileSystemProvider.USERNAME_PROPERTY;
import static java.util.Collections.emptyMap;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SmbFileSystemProviderTest {

    public static final String SHARE_NAME = "share";
    private static final String BASE_URI = "smb://user:password@server/" + SHARE_NAME;

    private final URI uri = URI.create(BASE_URI);

    @Mock
    private SmbFileSystemProvider.Factory factory;

    @Mock
    private SmbFileSystem fileSystem;

    @Captor
    private ArgumentCaptor<AuthenticationContext> authenticationContexts;

    private SmbFileSystemProvider provider;

    @BeforeEach
    void setUp() {
        provider = new SmbFileSystemProvider(factory);
    }

    @Nested
    class WithoutFileSystem {

        @Test
        void throwExceptionIfFileSystemNotCreated() {

            assertThrows(FileSystemNotFoundException.class, () -> provider.getFileSystem(uri));
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "smb://user:pw@/" + SHARE_NAME,
            "smb://user:pw@server/",
        })
        void throwsInvalidShareExceptionIfInvalidUri(URI uri) {

            Executable executable = () -> provider.newFileSystem(uri, emptyMap());
            assertThrows(InvalidShareException.class, executable);
        }

        @Test
        void createsFileSystem() throws Exception {
            when(factory.create(eq(provider), eq("server"), eq(SMBClient.DEFAULT_PORT), any(), eq(SHARE_NAME)))
                .thenReturn(fileSystem);

            SmbFileSystem fs = provider.newFileSystem(uri, emptyMap());

            assertSame(fileSystem, fs);
        }

        @ParameterizedTest
        @CsvSource({
            "domain;user:password,domain,user,password",
            "domain2;user2:password2,domain2,user2,password2",
            "user2:password2,,user2,password2",
            "user,,user,''",
            ":password,,'',password",
            "domain;,domain,'',''",
            "dom%3Fain;us%3Fer:pass%3Fword,dom?ain,us?er,pass?word",
        })
        void createsAuthenticationContextFromUri(String uriCredentials, String domain, String username, String password) throws Exception {
            when(factory.create(eq(provider), eq("server"), eq(SMBClient.DEFAULT_PORT), authenticationContexts.capture(), eq(SHARE_NAME)))
                .thenReturn(fileSystem);

            URI uri = URI.create("smb://" + uriCredentials + "@server/" + SHARE_NAME);

            SmbFileSystem fs = provider.newFileSystem(uri, emptyMap());

            assertSame(fileSystem, fs);

            assertEquals(1, authenticationContexts.getAllValues().size());
            AuthenticationContext context = authenticationContexts.getValue();
            assertEquals(domain, context.getDomain());
            assertEquals(username, context.getUsername());
            assertArrayEquals(password.toCharArray(), context.getPassword());
        }

        @ParameterizedTest
        @CsvSource({
            ",,,domain,username,password",
            "domain2,user2,password2,domain2,user2,password2",
            "domain2,,,domain2,username,password",
            ",user2,,domain,user2,password",
            ",,password2,domain,username,password2",
        })
        void createsAuthenticationContextFromUriAndEnv(String envDomain, String envUsername, String envPassword, String domain, String username, String password) throws Exception {
            when(factory.create(eq(provider), eq("server"), eq(SMBClient.DEFAULT_PORT), authenticationContexts.capture(), eq(SHARE_NAME)))
                .thenReturn(fileSystem);

            URI uri = URI.create("smb://domain;username:password@server/" + SHARE_NAME);

            Map<String, Object> env = new HashMap<>();
            if (envDomain != null)
                env.put(DOMAIN_PROPERTY, envDomain);
            if (envUsername != null)
                env.put(USERNAME_PROPERTY, envUsername);
            if (envPassword != null)
                env.put(PASSWORD_PROPERTY, envPassword);

            SmbFileSystem fs = provider.newFileSystem(uri, env);

            assertSame(fileSystem, fs);

            assertEquals(1, authenticationContexts.getAllValues().size());
            AuthenticationContext context = authenticationContexts.getValue();
            assertEquals(domain, context.getDomain());
            assertEquals(username, context.getUsername());
            assertArrayEquals(password.toCharArray(), context.getPassword());
        }


        @Test
        void throwExceptionWhenGettingPathFromUri() {

            assertThrows(FileSystemNotFoundException.class, () -> provider.getPath(uri));
        }
    }

    @Nested
    class WithFileSystem {

        @Mock
        private SmbFileSystem fileSystem2;

        @BeforeEach
        void setUp() throws Exception {
            when(factory.create(eq(provider), any(), anyInt(), any(), any()))
                .thenReturn(fileSystem, fileSystem2);

            provider.newFileSystem(uri, emptyMap());
        }

        @Test
        void throwExceptionIfFileSystemAlreadyCreated() {

            assertThrows(FileSystemAlreadyExistsException.class, () -> provider.newFileSystem(uri, emptyMap()));
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "smb://user:password@server2/" + SHARE_NAME,
            "smb://user2:password@server/" + SHARE_NAME,
            "smb://user:password@server/" + SHARE_NAME + "2",
        })
        void createsUnrelatedFilesystems(URI uri) throws Exception {
            SmbFileSystem other = provider.newFileSystem(uri, emptyMap());

            assertSame(fileSystem2, other);
        }

        @Test
        void returnsPreviouslyCreatedFileSystem() {

            FileSystem current = provider.getFileSystem(uri);

            assertSame(fileSystem, current);
        }

        @Test
        void removesFileSystem() throws Exception {
            provider.removeFileSystem(fileSystem);

            assertThrows(FileSystemNotFoundException.class, () -> provider.getFileSystem(uri));

            SmbFileSystem current = provider.newFileSystem(uri, emptyMap());

            assertNotSame(fileSystem, current);
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "/a.txt",
            "/asd/a.txt",
        })
        void getsPathFromUri(String path) {
            if (path == null)
                path = "";

            SmbPath result = SmbPath.of(fileSystem, null, "ads");

            when(fileSystem.share())
                    .thenReturn(SHARE_NAME);
            when(fileSystem.getPath(path))
                    .thenReturn(result);

            SmbPath actual = provider.getPath(URI.create(BASE_URI + path));

            assertSame(result, actual);
        }

        @ParameterizedTest
        @EmptySource
        @ValueSource(strings = {
            "/",
        })
        void getsRootPathFromUri(String path) {
            if (path == null)
                path = "";

            SmbPath result = SmbPath.of(fileSystem, null, "ads");

            when(fileSystem.share())
                    .thenReturn(SHARE_NAME);
            when(fileSystem.root())
                    .thenReturn(result);

            SmbPath actual = provider.getPath(URI.create(BASE_URI + path));

            assertSame(result, actual);
        }
    }
}
