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
import com.hierynomus.smbfs.SmbFileSystemProvider;
import com.hierynomus.smbfs.SmbPath;
import com.hierynomus.smbj.testcontainers.SambaContainer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;

import static integration.smbfs.RandomData.randomString;
import static java.util.Collections.emptyMap;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Testcontainers
public class FileWritingIntegrationTest {

    @Container
    private static final SambaContainer samba = SambaContainer.INSTANCE;

    private SmbFileSystemProvider provider;

    @BeforeEach
    void setUp() {
        provider = new SmbFileSystemProvider();
    }

    @AfterEach
    void tearDown() throws Exception {
        samba.deleteFromContainer("/opt/samba/user/written.txt");
        samba.deleteFromContainer("/opt/samba/user/test.txt");
    }

    @Test
    void writesFile() throws Exception {

        String data = randomString(23);

        try (SmbFileSystem fileSystem = provider.newFileSystem(samba.userUri(), emptyMap())) {

            SmbPath path = fileSystem.getPath("written.txt");

            try (OutputStream out = provider.newOutputStream(path)) {
                out.write(data.trim().getBytes(StandardCharsets.UTF_8));
            }
        }

        assertEquals(data, samba.readFileFromContainer("/opt/samba/user/written.txt"));
    }

    @Test
    void appendsToEmptyFile() throws Exception {

        String data = randomString(23);

        try (SmbFileSystem fileSystem = provider.newFileSystem(samba.userUri(), emptyMap())) {

            SmbPath path = fileSystem.getPath("written.txt");

            try (OutputStream out = provider.newOutputStream(path, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                out.write(data.getBytes(StandardCharsets.UTF_8));
            }
        }

        assertEquals(data, samba.readFileFromContainer("/opt/samba/user/written.txt"));
    }


    @Test
    void appendsToFile() throws Exception {
        String containerPath = "/opt/samba/user/test.txt";

        String initialData = randomString(14);
        String additionalData = randomString(12);

        //noinspection OctalInteger
        samba.copyFileToContainer(Transferable.of(initialData, 0100666), containerPath);

        try (SmbFileSystem fileSystem = provider.newFileSystem(samba.userUri(), emptyMap())) {

            SmbPath path = fileSystem.getPath("test.txt");

            try (OutputStream out = provider.newOutputStream(path, StandardOpenOption.APPEND)) {
                out.write(additionalData.getBytes(StandardCharsets.UTF_8));
            }
        }

        assertEquals(initialData + additionalData, samba.readFileFromContainer(containerPath));
    }
}
