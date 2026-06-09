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

import com.hierynomus.smbj.testcontainers.SambaContainer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.Writer;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

import static integration.smbfs.RandomData.randomString;
import static java.util.Collections.emptyMap;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Set of common patterns using the java.nio.file package.
 */
@Testcontainers
public class JavaNioIntegrationTest {

    @Container
    private static final SambaContainer samba = SambaContainer.INSTANCE;
    private FileSystem fileSystem;

    @BeforeEach
    void setUp() throws Exception {
        fileSystem = FileSystems.newFileSystem(samba.userUri(), emptyMap());
    }

    @AfterEach
    void tearDown() throws Exception {
        fileSystem.close();
    }

    @Test
    void writesFileForImportByAnotherApplication() throws Exception {

        String data = randomString(1000);

        URI fileUri = samba.userUri().resolve("export/file.txt");
        URI archiveUri = samba.userUri().resolve("archive");

        Path path = Paths.get(fileUri);

        // Write a file with a temporary name to ensure nobody reads while writing
        Path workingPath = path.resolveSibling(path.getFileName().toString() + ".working");
        Files.createDirectories(workingPath.getParent());
        try (Writer w = Files.newBufferedWriter(workingPath)) {
            w.write(data);
        }

        // copy the file into an archive folder sharded by date to keep the file count in each folder small(ish)
        Path rootArchivePath = Paths.get(archiveUri);
        String archiveFolderName = DateTimeFormatter.ofPattern("yyyy/MM/dd").format(LocalDate.now());
        Path archiveFile = rootArchivePath.resolve(archiveFolderName)
            .resolve(path.getFileName());
        Files.createDirectories(archiveFile.getParent());
        Files.copy(workingPath, archiveFile);

        // rename file to target file
        Files.move(workingPath, path);

        assertEquals(data, Files.readAllLines(path).get(0));
        assertEquals(data, Files.readAllLines(archiveFile).get(0));
    }
}
