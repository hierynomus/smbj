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

import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbfs.SmbFileSystem;
import com.hierynomus.smbfs.SmbFileSystemProvider;
import com.hierynomus.smbfs.SmbPath;
import com.hierynomus.smbj.testcontainers.SambaContainer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static integration.smbfs.RandomData.randomString;
import static java.util.Collections.emptyMap;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Testcontainers
public class FileMoveIntegrationTest {

    @Container
    private final SambaContainer samba = SambaContainer.INSTANCE;

    private SmbFileSystemProvider provider;

    @BeforeEach
    void setUp() throws Exception {
        samba.mkdirInContainer("/opt/samba/user/a");
        samba.mkdirInContainer("/opt/samba/user/b");

        provider = new SmbFileSystemProvider();
    }

    @ParameterizedTest
    @CsvSource({
        "source.txt,target.txt",
        "a/source.txt,a/target.txt",
        "a/source.txt,target.txt",
        "source.txt,a/target.txt",
        "a/source.txt,b/target.txt",
    })
    void movesFileOnsSameShare(String sourceFile, String targetFile) throws Exception {

        String data = randomString(23);
        Transferable transferable = Transferable.of(data);
        samba.copyFileToContainer(transferable, "/opt/samba/user/" + sourceFile);

        try (SmbFileSystem fileSystem = provider.newFileSystem(samba.userUri(), emptyMap())) {
            SmbPath source = fileSystem.getPath(sourceFile);
            SmbPath target = fileSystem.getPath(targetFile);
            fileSystem.provider().move(source, target);
        }

        assertEquals(data, samba.readFileFromContainer("/opt/samba/user/" + targetFile));
    }

    @ParameterizedTest
    @CsvSource({
        "source.txt,target.txt",
        "a/source.txt,a/target.txt",
        "a/source.txt,target.txt",
        "source.txt,a/target.txt",
        "a/source.txt,b/target.txt",
    })
    void failsToOverwrite(String sourceFile, String targetFile) throws Exception {

        String data = randomString(23);
        Transferable transferable = Transferable.of(data);
        samba.copyFileToContainer(transferable, "/opt/samba/user/" + sourceFile);
        samba.copyFileToContainer(Transferable.of("RUBBISH"), "/opt/samba/user/" + targetFile);

        try (SmbFileSystem fileSystem = provider.newFileSystem(samba.userUri(), emptyMap())) {
            SmbPath source = fileSystem.getPath(sourceFile);
            SmbPath target = fileSystem.getPath(targetFile);
            assertThrows(SMBApiException.class, () -> fileSystem.provider().move(source, target));
        }
    }

    @Test
    void movesFilesOnDifferentShares() throws Exception {

        String data = randomString(23);
        Transferable transferable = Transferable.of(data);
        samba.copyFileToContainer(transferable, "/opt/samba/share/source.txt");

        try (SmbFileSystem fileSystem = provider.newFileSystem(samba.publicUri(), emptyMap());
             SmbFileSystem targetFileSystem = provider.newFileSystem(samba.userUri(), emptyMap())) {

            SmbPath source = fileSystem.getPath("source.txt");
            SmbPath target = targetFileSystem.getPath("target.txt");
            fileSystem.provider().move(source, target);
        }

        assertEquals(data, samba.readFileFromContainer("/opt/samba/user/target.txt"));
        assertFalse(samba.fileExistsInContainer("/opt/samba/share/source.txt"));
    }
}
