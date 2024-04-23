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
package integration.smbfs;

import com.hierynomus.smbfs.SmbFileSystem;
import com.hierynomus.smbj.testcontainers.SambaContainer;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;

import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;

import static com.hierynomus.smbj.testing.TestingUtils.PASSWORD;
import static com.hierynomus.smbj.testing.TestingUtils.USER;
import static java.util.Collections.emptyMap;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class FileSystemIntegrationTest {

    @Container
    private static final SambaContainer samba = SambaContainer.INSTANCE;

    @Test
    void createsAndClosesFilesystem() throws Exception {

        URI uri = URI.create("smb://" + USER + ":" + PASSWORD + "@" + samba.getHost() + "/user");
        try (FileSystem fileSystem = FileSystems.newFileSystem(uri, emptyMap())) {
            assertNotNull(fileSystem);
            assertInstanceOf(SmbFileSystem.class, fileSystem);
        }
    }
}
