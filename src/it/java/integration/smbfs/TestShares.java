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
import org.junit.jupiter.params.provider.Arguments;

import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystemAlreadyExistsException;
import java.util.Map;
import java.util.stream.Stream;

import static com.hierynomus.smbfs.SmbFileSystemProvider.DFS_ENABLED_PROPERTY;
import static java.util.Collections.emptyMap;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class TestShares {

    static Stream<String> allPublicShares() {
        return Stream.of(
            "public",
            "dfs/public"
        );
    }

    static Stream<String> allUserShares() {
        return Stream.of(
            "user",
            "dfs/user"
        );
    }

    static Stream<Arguments> allPublicToUserShares() {
        return Stream.of(
            arguments("public", "user"),
            arguments("public", "dfs/user"),
            arguments("dfs/public", "user")
            // This doesn't work at the moment for moving & copying files
            // arguments("dfs/public", "dfs/user")
        );
    }

    private TestShares() {
    }

    static void withFileSystemProvider(SambaContainer samba, String share,
                                       BiConsumerWithError<SmbFileSystemProvider, SmbPath> with) throws Exception {

        SmbFileSystemProvider provider = new SmbFileSystemProvider();
        withFileSystem(provider, samba, share, with);
    }

    static void withFileSystem(SmbFileSystemProvider provider, SambaContainer samba, String share,
                               BiConsumerWithError<SmbFileSystemProvider, SmbPath> with)
        throws Exception {
        URI uri = samba.shareUri(share);
        Map<String, Object> env = share.startsWith("dfs/")
            ? Map.of(DFS_ENABLED_PROPERTY, true)
            : emptyMap();
        try (SmbFileSystem ignored = getOrNewFileSystem(provider, uri, env)) {
            with.with(provider, provider.getPath(uri));
        }
    }

    // temporary method to get integration tests working
    private static SmbFileSystem getOrNewFileSystem(SmbFileSystemProvider provider, URI uri, Map<String, ?> env) throws IOException {
        try {
            return provider.newFileSystem(uri, env);
        } catch (FileSystemAlreadyExistsException e) {
            return provider.getFileSystem(uri);
        }
    }

    @FunctionalInterface
    interface BiConsumerWithError<T, U> {
        void with(T provider, U path) throws Exception;
    }
}

