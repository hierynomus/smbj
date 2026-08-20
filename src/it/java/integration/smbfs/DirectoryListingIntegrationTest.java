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
import com.hierynomus.smbj.testcontainers.SambaContainer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static integration.smbfs.TestShares.withFileSystemProvider;
import static java.util.Collections.emptyMap;
import static java.util.stream.Collectors.toList;
import static java.util.stream.StreamSupport.stream;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Testcontainers
class DirectoryListingIntegrationTest {

    @Container
    private static final SambaContainer samba = SambaContainer.INSTANCE;

    private SmbFileSystemProvider provider;

    @BeforeEach
    void setUp() {
        provider = new SmbFileSystemProvider();
    }

    @Test
    void returnsRootDirectories() throws Exception {
        try (SmbFileSystem fileSystem = provider.newFileSystem(samba.publicUri(), emptyMap())) {

            List<String> dirs = stream(fileSystem.getRootDirectories().spliterator(), false)
                .map(Object::toString)
                .collect(toList());

            assertEquals(List.of("\\"), dirs);
        }
    }

    static Stream<Arguments> listDirectoriesArguments() {
        return  Stream.of(
            Arguments.arguments("public", List.of("\\folder", "\\test.txt")),
            Arguments.arguments("dfs/public", List.of("\\public\\folder", "\\public\\test.txt"))

        );
    }

    @ParameterizedTest
    @MethodSource("listDirectoriesArguments")
    void listsDirectories(String share, List<String> contents) throws Exception {

        withFileSystemProvider(samba, share, (provider, base) -> {

            List<String> actual = list(provider, base);

            assertEquals(contents.stream().sorted().collect(toList()),
                         actual.stream().sorted().collect(toList()));
        });
    }

    private List<String> list(SmbFileSystemProvider provider, Path path) throws IOException {
        try (DirectoryStream<Path> stream = provider.newDirectoryStream(path, f -> true)) {
            return StreamSupport.stream(stream.spliterator(), false)
                .map(Path::toString)
                .collect(Collectors.toList());
        }
    }
}
