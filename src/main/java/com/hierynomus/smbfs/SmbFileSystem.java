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

import com.hierynomus.msfscc.fileinformation.FileAllInformation;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;

import java.io.IOException;
import java.nio.file.AccessMode;
import java.nio.file.DirectoryStream;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static com.hierynomus.smbfs.ToBeImplementedException.toBeImplemented;
import static java.util.Collections.singletonList;

public class SmbFileSystem extends FileSystem {
    private static final String SEPARATOR = "" + SmbPath.SEPARATOR;

    private final SmbFileSystemProvider provider;

    private final Connection connection;
    private final Session session;
    private final String share;

    private final SmbPath root = SmbPath.root(this);

    private volatile boolean open;

    SmbFileSystem(SmbFileSystemProvider provider, Connection connection, Session session, String share) {
        this.provider = provider;
        this.connection = connection;
        this.session = session;
        this.share = share;
    }

    @Override
    public SmbFileSystemProvider provider() {
        return provider;
    }

    @Override
    @SuppressWarnings("unused")
    public void close() throws IOException {
        // this will close the session, then connection - handling any suppressed exceptions, etc.
        try (Connection c = connection;
             Session s = session) {

            open = false;
            provider.removeFileSystem(this);
        }
    }

    @Override
    public boolean isOpen() {
        return open;
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public String getSeparator() {
        return SEPARATOR;
    }

    @Override
    public Iterable<Path> getRootDirectories() {
        return singletonList(root);
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
    public SmbPath getPath(String first, String... more) {
        return SmbPath.of(this, null, first, more);
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

    DirectoryStream<Path> newDirectoryStream(Path path, DirectoryStream.Filter<? super Path> filter)
        throws IOException {

        try (DiskShare ds = (DiskShare) session.connectShare(share)) {
            List<Path> list = new ArrayList<>();

            for (FileIdBothDirectoryInformation each : ds.list(path.toString())) {
                String name = each.getFileName();
                if (name.equals(".") || name.equals(".."))
                    continue;

                Path eachPath = path.resolve(name);

                if (!filter.accept(eachPath))
                    continue;

                list.add(eachPath);
            }

            return new SmbDirectoryStream(list);
        }
    }

    <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> type) throws IOException {

        if (type != BasicFileAttributes.class)
            throw new UnsupportedOperationException(type.getName());

        try {
            try (DiskShare ds = (DiskShare) session.connectShare(share)) {
                FileAllInformation fileInformation = ds.getFileInformation(path.toString());

                return type.cast(new SmbFileAttributes(fileInformation));
            }
        } catch (SMBApiException e) {
            throw new IOException(e);
        }
    }

    void checkAccess(Path path, AccessMode... modes) throws IOException {
        try {
            try (DiskShare ds = (DiskShare) session.connectShare(share)) {
                ds.getFileInformation(path.toString());
            }
        } catch (SMBApiException e) {
            throw new IOException(e);
        }
    }
}
