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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static integration.smbfs.RandomData.randomString;
import static integration.smbfs.TestShares.withFileSystem;
import static integration.smbfs.TestShares.withFileSystemProvider;
import static java.util.Collections.emptyMap;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Testcontainers
public class FileCopyIntegrationTest {

    @Container
    private static final SambaContainer samba = SambaContainer.INSTANCE;

    private SmbFileSystemProvider provider;

    @BeforeEach
    void setUp() {
        provider = new SmbFileSystemProvider();
    }

    @AfterEach
    void tearDown() throws Exception {
        samba.deleteFromContainer("/opt/samba/user/source.txt");
        samba.deleteFromContainer("/opt/samba/user/target.txt");
        samba.deleteFromContainer("/opt/samba/share/source.txt");
    }

    @Test
    void copiesFileOnSameShare() throws Exception {

        String data = randomString(23);
        Transferable transferable = Transferable.of(data);
        samba.copyFileToContainer(transferable, "/opt/samba/user/source.txt");

        try (SmbFileSystem fileSystem = provider.newFileSystem(samba.userUri(), emptyMap())) {
            SmbPath source = fileSystem.getPath("source.txt");
            SmbPath target = fileSystem.getPath("target.txt");
            fileSystem.provider().copy(source, target);
        }

        assertEquals(data, samba.readFileFromContainer("/opt/samba/user/target.txt"));
    }

    @Nested
    @ParameterizedClass
    @MethodSource("integration.smbfs.TestShares#allPublicToUserShares")
    class WithDifferentShares {

        private final String publicShare;
        private final String userShare;

        WithDifferentShares(String publicShare, String userShare) {
            this.publicShare = publicShare;
            this.userShare = userShare;
        }

        @Test
        void copiesFileOnDifferentShares() throws Exception {

            String data = randomString(33);
            Transferable transferable = Transferable.of(data);
            samba.copyFileToContainer(transferable, "/opt/samba/share/source.txt");

            withFileSystemProvider(samba, publicShare, (provider, publicBase) -> {
                withFileSystem(provider, samba, userShare, (ignored, userBase) -> {
                    SmbPath source = publicBase.resolve("source.txt");
                    SmbPath target = userBase.resolve("target.txt");

                    provider.copy(source, target);
                });
            });

            assertEquals(data, samba.readFileFromContainer("/opt/samba/user/target.txt"));
        }
    }
}
