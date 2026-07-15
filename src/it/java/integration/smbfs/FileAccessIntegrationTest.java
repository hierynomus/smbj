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
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.util.stream.Stream;

import static integration.smbfs.TestShares.withFileSystemProvider;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

@ParameterizedClass
@MethodSource("integration.smbfs.TestShares#allPublicShares")
@Testcontainers
class FileAccessIntegrationTest {

    @Container
    private static final SambaContainer samba = SambaContainer.INSTANCE;

    private final String share;

    FileAccessIntegrationTest(String share) {
        this.share = share;
    }

    static Stream<Arguments> filesThatExist() {
        return Stream.of(
            arguments("folder"),
            arguments("folder/do_not_remove"),
            arguments("test.txt")
        );
    }

    @ParameterizedTest
    @MethodSource("filesThatExist")
    void fileExists(String path) throws Exception {

        withFileSystemProvider(samba, share, (provider, base) -> {

            SmbPath path1 = base.resolve(path);

            provider.checkAccess(path1);
        });
    }

    static Stream<Arguments> filesThatDontExist() {
        return Stream.of(
            arguments("missing"),
            arguments("folder/missing")
        );
    }

    @ParameterizedTest
    @MethodSource("filesThatDontExist")
    void fileMissing(String path) throws Exception {

        withFileSystemProvider(samba, share, (provider, base) -> {

            SmbPath path1 = base.resolve(path);
            assertThrows(IOException.class, () -> provider.checkAccess(path1));
        });
    }
}
