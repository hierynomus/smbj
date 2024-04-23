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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.fileinformation.FileAllInformation;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.DirectoryStream;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.StandardOpenOption;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
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

    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>[] attrs) {

        Set<AccessMask> accessMasks = accessMasks(options);
        SMB2CreateDisposition disposition = createDisposition(options);
        Set<SMB2CreateOptions> createOptions = createOptions(options);

        DiskShare ds = (DiskShare) session.connectShare(share);
        File file = ds.openFile(path.toString(), accessMasks, null, null, disposition, createOptions);
        long position = 0;
        if (options.contains(StandardOpenOption.APPEND))
            position = file.getLength();

        return new SmbFileChannel(ds, file, position);
    }

    private static Set<AccessMask> accessMasks(Set<? extends OpenOption> options) {
        boolean read = options.contains(StandardOpenOption.READ);
        boolean write = options.contains(StandardOpenOption.WRITE);
        boolean append = write && options.contains(StandardOpenOption.APPEND);

        if (options.contains(StandardOpenOption.DELETE_ON_CLOSE))
            throw toBeImplemented();

        EnumSet<AccessMask> accessMasks = EnumSet.noneOf(AccessMask.class);

        if (append)
            accessMasks.add(AccessMask.FILE_APPEND_DATA);
        else if (write)
            accessMasks.add(AccessMask.FILE_WRITE_DATA);

        // Files doesn't seem to set READ when creating inputStreams... only WRITE
        if (read || !write)
            accessMasks.add(AccessMask.FILE_READ_DATA);

        return accessMasks;
    }

    private static SMB2CreateDisposition createDisposition(Set<? extends OpenOption> options) {
        if (options.contains(StandardOpenOption.CREATE_NEW))
            return SMB2CreateDisposition.FILE_CREATE;

        if (options.contains(StandardOpenOption.WRITE) &&
            options.contains(StandardOpenOption.TRUNCATE_EXISTING)) {

            return SMB2CreateDisposition.FILE_OVERWRITE_IF;
        }

        if (options.contains(StandardOpenOption.CREATE))
            return SMB2CreateDisposition.FILE_OPEN_IF;

        return SMB2CreateDisposition.FILE_OPEN;
    }

    private static Set<SMB2CreateOptions> createOptions(Set<? extends OpenOption> options) {
        if (options.contains(StandardOpenOption.DSYNC) || options.contains(StandardOpenOption.SYNC))
            return EnumSet.of(SMB2CreateOptions.FILE_WRITE_THROUGH);

        return null;
    }

    public void copy(Path source, Path target) throws IOException {
        Set<StandardOpenOption> readOptions = Collections.singleton(StandardOpenOption.READ);
        Set<StandardOpenOption> writeOptions = new HashSet<>(Arrays.asList(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW));

        try (DiskShare ds = (DiskShare) session.connectShare(share);
             File sourceFile = ds.openFile(source.toString(), accessMasks(readOptions), null, null, createDisposition(readOptions), createOptions(readOptions));
             File destinationFile = ds.openFile(target.toString(), accessMasks(writeOptions), null, null, createDisposition(writeOptions), createOptions(writeOptions))) {

            sourceFile.remoteCopyTo(destinationFile);

        } catch (Buffer.BufferException e) {
            throw new IOException(e);
        }
    }
}
