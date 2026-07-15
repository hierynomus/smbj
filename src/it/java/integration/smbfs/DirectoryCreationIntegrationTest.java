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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static integration.smbfs.TestShares.withFileSystemProvider;

@ParameterizedClass
@MethodSource("integration.smbfs.TestShares#allUserShares")
@Testcontainers
class DirectoryCreationIntegrationTest {

    @Container
    private static final SambaContainer samba = SambaContainer.INSTANCE;

    private final String share;

    DirectoryCreationIntegrationTest(String share) {
        this.share = share;
    }

    @AfterEach
    void tearDown() throws Exception {
        samba.deleteFromContainer("/opt/samba/user/a");
    }

    @Test
    void createsDirectory() throws Exception {

        withFileSystemProvider(samba, share, (provider, base) -> {

            SmbPath path = base.resolve("a");
            provider.createDirectory(path);
        });

        samba.dirExistsInContainer("/opt/samba/user/a");
    }
}
