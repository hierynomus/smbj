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

import com.hierynomus.smbfs.SmbPath;
import com.hierynomus.smbj.testcontainers.SambaContainer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static integration.smbfs.RandomData.randomString;
import static integration.smbfs.TestShares.withFileSystemProvider;
import static org.junit.jupiter.api.Assertions.assertFalse;

@ParameterizedClass
@MethodSource("integration.smbfs.TestShares#allUserShares")
@Testcontainers
public class FileDeleteIntegrationTest {

    @Container
    private static final SambaContainer samba = SambaContainer.INSTANCE;

    private final String share;

    FileDeleteIntegrationTest(String share) {
        this.share = share;
    }

    @BeforeEach
    void setUp() throws Exception {
        samba.mkdirInContainer("/opt/samba/user/a");
    }

    @AfterEach
    void tearDown() throws Exception {
        samba.deleteFromContainer("/opt/samba/user/a");
    }

    @ParameterizedTest
    @CsvSource({
        "source.txt",
        "a/source.txt",
    })
    void deletesFiles(String file) throws Exception {

        String data = randomString(23);
        Transferable transferable = Transferable.of(data);
        samba.copyFileToContainer(transferable, "/opt/samba/user/" + file);

        withFileSystemProvider(samba, share, (provider, base) -> {
            SmbPath path = base.resolve(file);
            provider.delete(path);
        });

        assertFalse(samba.fileExistsInContainer("/opt/samba/user/" + file));
    }
}
