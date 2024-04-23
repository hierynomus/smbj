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
package com.hierynomus.smbfs;

import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.WatchService;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.Set;

import static com.hierynomus.smbfs.ToBeImplementedException.toBeImplemented;

public class SmbFileSystem extends FileSystem {
    private final SmbFileSystemProvider provider;

    private volatile boolean open;

    SmbFileSystem(SmbFileSystemProvider provider) {
        this.provider = provider;
    }

    @Override
    public SmbFileSystemProvider provider() {
        return provider;
    }

    @Override
    public void close() {
        open = false;
        provider.removeFileSystem(this);
    }

    @Override
    public boolean isOpen() {
        return open;
    }

    @Override
    public boolean isReadOnly() {
        throw toBeImplemented();
    }

    @Override
    public String getSeparator() {
        throw toBeImplemented();
    }

    @Override
    public Iterable<Path> getRootDirectories() {
        throw toBeImplemented();
    }

    @Override
    public Iterable<FileStore> getFileStores() {
        throw toBeImplemented();
    }

    @Override
    public Set<String> supportedFileAttributeViews() {
        throw toBeImplemented();
    }

    @Override
    public Path getPath(String first, String... more) {
        throw toBeImplemented();
    }

    @Override
    public PathMatcher getPathMatcher(String syntaxAndPattern) {
        throw toBeImplemented();
    }

    @Override
    public UserPrincipalLookupService getUserPrincipalLookupService() {
        throw toBeImplemented();
    }

    @Override
    public WatchService newWatchService() {
        throw toBeImplemented();
    }
}
