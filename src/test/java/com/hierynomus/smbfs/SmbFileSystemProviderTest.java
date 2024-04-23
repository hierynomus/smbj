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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;

import static java.util.Collections.emptyMap;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SmbFileSystemProviderTest {

    private final URI uri = URI.create("smb://user:password@server/share");
    private final SmbFileSystemProvider provider = new SmbFileSystemProvider();

    @Nested
    class WithoutFileSystem {

        @Test
        void throwExceptionIfFileSystemNotCreated() {

            assertThrows(FileSystemNotFoundException.class, () -> provider.getFileSystem(uri));
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "smb://user:pw@/share",
            "smb://user:pw@server/",
            "smb://server/share",
        })
        void throwsInvalidShareExceptionIfInvalidUri(URI uri) {

            Executable executable = () -> provider.newFileSystem(uri, emptyMap());
            assertThrows(InvalidShareException.class, executable);
        }

        @Test
        void createsFileSystem() {
            SmbFileSystem fs = provider.newFileSystem(uri, emptyMap());

            assertNotNull(fs);
        }
    }

    @Nested
    class WithFileSystem {

        private SmbFileSystem fileSystem;

        @BeforeEach
        void setUp() {
            fileSystem = provider.newFileSystem(uri, emptyMap());
        }

        @Test
        void throwExceptionIfFileSystemAlreadyCreated() {

            assertThrows(FileSystemAlreadyExistsException.class, () -> provider.newFileSystem(uri, emptyMap()));
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "smb://user:password@server2/share",
            "smb://user2:password@server/share",
            "smb://user:password@server/share2",
        })
        void createsUnrelatedFilesystems(URI uri) {

            SmbFileSystem other = provider.newFileSystem(uri, emptyMap());

            assertNotSame(fileSystem, other);
        }

        @Test
        void returnsPreviouslyCreatedFileSystem() {

            FileSystem current = provider.getFileSystem(uri);

            assertSame(fileSystem, current);
        }

        @Test
        void returnsSameFileSystemIfFileSystemAlreadyCreatedExceptWithDifferentPassword() {
            FileSystem current = provider.getFileSystem(URI.create("smb://user:XXXXX@server/share"));

            assertSame(fileSystem, current);
        }

        @Test
        void removesFileSystem() {

            provider.removeFileSystem(fileSystem);

            assertThrows(FileSystemNotFoundException.class, () -> provider.getFileSystem(uri));

            SmbFileSystem current = provider.newFileSystem(uri, emptyMap());

            assertNotSame(fileSystem, current);
        }
    }
}
