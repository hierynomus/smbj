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

import java.net.URI;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileStore;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static com.hierynomus.smbfs.ToBeImplementedException.toBeImplemented;

public class SmbFileSystemProvider extends FileSystemProvider {

    private static final String SCHEME = "smb";

    private final Map<String, SmbFileSystem> fileSystems = new HashMap<>();

    @Override
    public String getScheme() {
        return SCHEME;
    }

    @Override
    public SmbFileSystem newFileSystem(URI uri, Map<String, ?> env) {
        String key = getKey(uri);

        synchronized (fileSystems) {
            if (fileSystems.containsKey(key))
                throw new FileSystemAlreadyExistsException(key);

            SmbFileSystem fileSystem = new SmbFileSystem(this);
            fileSystems.put(key, fileSystem);
            return fileSystem;
        }
    }

    @Override
    public SmbFileSystem getFileSystem(URI uri) {
        String key = getKey(uri);
        synchronized (fileSystems) {
            if (!fileSystems.containsKey(key))
                throw new FileSystemNotFoundException(uri.toString());

            return fileSystems.get(key);
        }
    }

    private String getKey(URI uri) {
        String userInfo = extractUser(uri);
        String host = extractHost(uri);
        String shareName = extractShareName(uri);

        return userInfo + "@" + host + "/" + shareName;
    }

    private String extractUser(URI uri) {
        String userInfo = uri.getUserInfo();
        if (userInfo == null || userInfo.isEmpty()) {
            throw new InvalidShareException(uri.toString());
        }

        int p = userInfo.indexOf(':');
        if (p >= 0)
            return userInfo.substring(0, p);

        return userInfo;
    }

    private String extractHost(URI uri) {
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new InvalidShareException(uri.toString());
        }

        return host;
    }

    private String extractShareName(URI uri) {
        String share = uri.getPath();

        if (share != null && !share.isEmpty()) {
            String[] bits = share.split("/");

            if (bits.length > 1)
                return bits[1];
        }

        throw new InvalidShareException(uri.toString());
    }

    void removeFileSystem(SmbFileSystem fileSystem) {
        synchronized (fileSystems) {
            for (Map.Entry<String, SmbFileSystem> each : fileSystems.entrySet()) {
                if (each.getValue() == fileSystem) {
                    fileSystems.remove(each.getKey());
                    return;
                }
            }
        }
    }

    @Override
    public Path getPath(URI uri) {
        throw toBeImplemented();
    }

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs) {
        throw toBeImplemented();
    }

    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir, DirectoryStream.Filter<? super Path> filter) {
        throw toBeImplemented();
    }

    @Override
    public void createDirectory(Path dir, FileAttribute<?>... attrs) {
        throw toBeImplemented();
    }

    @Override
    public void delete(Path path) {
        throw toBeImplemented();
    }

    @Override
    public void copy(Path source, Path target, CopyOption... options) {
        throw toBeImplemented();
    }

    @Override
    public void move(Path source, Path target, CopyOption... options) {
        throw toBeImplemented();
    }

    @Override
    public boolean isSameFile(Path path, Path path2) {
        throw toBeImplemented();
    }

    @Override
    public boolean isHidden(Path path) {
        throw toBeImplemented();
    }

    @Override
    public FileStore getFileStore(Path path) {
        throw toBeImplemented();
    }

    @Override
    public void checkAccess(Path path, AccessMode... modes) {
        throw toBeImplemented();
    }

    @Override
    public <V extends FileAttributeView> V getFileAttributeView(Path path, Class<V> type, LinkOption... options) {
        throw toBeImplemented();
    }

    @Override
    public <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> type, LinkOption... options) {
        throw toBeImplemented();
    }

    @Override
    public Map<String, Object> readAttributes(Path path, String attributes, LinkOption... options) {
        throw toBeImplemented();
    }

    @Override
    public void setAttribute(Path path, String attribute, Object value, LinkOption... options) {
        throw toBeImplemented();
    }
}
