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

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.ProviderMismatchException;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.stream.IntStream;

import static com.hierynomus.smbfs.ToBeImplementedException.toBeImplemented;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;

public final class SmbPath implements Path {

    public static final char SEPARATOR = '\\';

    private final SmbFileSystem fileSystem;
    private final SmbPath root;
    private final List<String> elements;

    private SmbPath(SmbFileSystem fileSystem, SmbPath root, List<String> elements) {
        this.fileSystem = fileSystem;
        this.root = root;
        this.elements = elements;
    }

    private boolean isRoot() {
        return elements.isEmpty();
    }

    private boolean isChild() {
        return !elements.isEmpty();
    }

    @Override
    public SmbFileSystem getFileSystem() {
        return fileSystem;
    }

    @Override
    public boolean isAbsolute() {
        return root != null || isRoot();
    }

    @Override
    public SmbPath getRoot() {
        if (isRoot())
            return this;

        return root;
    }

    @Override
    public SmbPath getFileName() {
        if (isChild()) {
            int size = elements.size();
            return withNoRoot(elements.subList(size - 1, size));
        }

        return null;
    }

    @Override
    public SmbPath getParent() {
        if (isChild() && elements.size() > 1)
            return withSameRoot(elements.subList(0, elements.size() - 1));

        return root;
    }

    @Override
    public int getNameCount() {
        if (isChild())
            return elements.size();

        return 0;
    }

    @Override
    public SmbPath getName(int index) {
        if (isRoot())
            throw new IllegalArgumentException();
        if (index < 0)
            throw new IllegalArgumentException();
        if (index >= elements.size())
            throw new IllegalArgumentException();

        return withNoRoot(elements.subList(index, index + 1));
    }

    @Override
    public SmbPath subpath(int beginIndex, int endIndex) {
        if (isRoot())
            throw new IllegalArgumentException();
        if (beginIndex < 0 || beginIndex >= elements.size())
            throw new IllegalArgumentException("beginIndex");
        if (endIndex <= beginIndex || endIndex > elements.size())
            throw new IllegalArgumentException("endIndex");

        return withNoRoot(elements.subList(beginIndex, endIndex));
    }

    @Override
    public boolean startsWith(Path path) {
        SmbPath smbPath = requireSmbPath(path);

        if (fileSystem != smbPath.fileSystem)
            return false;

        if (getRoot() != smbPath.getRoot())
            return false;

        if (smbPath.elements.size() > elements.size())
            return false;

        for (int i = 0; i < smbPath.elements.size(); i++) {
            if (!elements.get(i).equals(smbPath.elements.get(i)))
                return false;
        }

        return true;
    }

    @Override
    public boolean startsWith(String other) {
        return startsWith(getFileSystem().getPath(other));
    }

    @Override
    public boolean endsWith(Path path) {
        throw toBeImplemented();
    }

    @Override
    public boolean endsWith(String other) {
        throw toBeImplemented();
    }

    @Override
    public SmbPath normalize() {
        throw toBeImplemented();
    }

    @Override
    public SmbPath resolve(Path suffix) {
        SmbPath other = requireSmbPath(suffix);

        if (other.isAbsolute())
            return other;

        List<String> elements = new ArrayList<>();
        elements.addAll(this.elements);
        elements.addAll(other.elements);

        if (isRoot())
            return withThisRoot(elements);

        return withSameRoot(elements);
    }

    @Override
    public SmbPath resolve(String other) {
        // This can be removed when JDK 11+ as the interface provides a default implementation
        return resolve(getFileSystem().getPath(other));
    }

    @Override
    public SmbPath resolveSibling(Path other) {
        // This can be removed when JDK 11+ as the interface provides a default implementation
        SmbPath otherSmb = requireSmbPath(requireNonNull(other));

        SmbPath parent = getParent();
        return (parent == null) ? otherSmb : parent.resolve(other);
    }

    @Override
    public SmbPath resolveSibling(String other) {
        // This can be removed when JDK 11+ as the interface provides a default implementation
        return resolveSibling(getFileSystem().getPath(other));
    }

    @Override
    public SmbPath relativize(Path other) {
        throw toBeImplemented();
    }

    @Override
    public URI toUri() {
        throw toBeImplemented();
    }

    @Override
    public SmbPath toAbsolutePath() {
        if (isAbsolute())
            return this;

        throw new IllegalStateException("No default dir");
    }

    @Override
    public SmbPath toRealPath(LinkOption... options) {
        throw toBeImplemented();
    }

    @Override
    public File toFile() {
        throw new UnsupportedOperationException("Path not associated with default file system");
    }

    @Override
    public WatchKey register(WatchService watcher, WatchEvent.Kind<?>... events) throws IOException {
        throw toBeImplemented();
    }

    @Override
    public WatchKey register(WatchService watcher, WatchEvent.Kind<?>[] events, WatchEvent.Modifier... modifiers) {
        throw toBeImplemented();
    }

    @Override
    public int compareTo(Path other) {
        return toString().toLowerCase()
            .compareTo(other.toString().toLowerCase());
    }

    @Override
    public Iterator<Path> iterator() {
        return IntStream.range(0, elements.size() - 1)
            .mapToObj(i -> (Path) getName(i))
            .iterator();
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;

        if (!(o instanceof SmbPath))
            return false;

        SmbPath other = (SmbPath) o;
        return Objects.equals(fileSystem, other.fileSystem) &&
            Objects.equals(root, other.root) &&
            Objects.equals(elements, other.elements);
    }

    @Override
    public int hashCode() {
        return Objects.hash(fileSystem, root, elements);
    }

    @Override
    public String toString() {
        if (elements == null)
            return "" + SEPARATOR;

        StringBuilder b = new StringBuilder();

        if (isAbsolute())
            b.append(SEPARATOR);

        for (int i = 0; i < elements.size(); i++) {
            if (i > 0)
                b.append(SEPARATOR);

            b.append(elements.get(i));
        }

        return b.toString();
    }

    private SmbPath withNoRoot(List<String> elements) {
        return of(fileSystem, null, elements);
    }

    private SmbPath withThisRoot(List<String> elements) {
        return of(fileSystem, this, elements);
    }

    private SmbPath withSameRoot(List<String> elements) {
        return of(fileSystem, root, elements);
    }

    static SmbPath root(SmbFileSystem smbFileSystem) {
        return new SmbPath(smbFileSystem, null, emptyList());
    }

    static SmbPath of(SmbFileSystem fileSystem, SmbPath rootPath, List<String> elements) {
        if (elements.isEmpty())
            throw new IllegalArgumentException();

        for (String each : elements) {
            if (each.isEmpty())
                throw new IllegalArgumentException();
        }

        return new SmbPath(fileSystem, rootPath, elements);
    }

    static SmbPath of(SmbFileSystem fileSystem, SmbPath rootPath, String element) {
        return of(fileSystem, rootPath, singletonList(element));
    }

    static SmbPath parse(SmbFileSystem fileSystem, SmbPath rootPath, String path) {
        List<String> elements = new ArrayList<>(Arrays.asList(path.split("" + SEPARATOR + SEPARATOR)));

        return of(fileSystem, rootPath, elements);
    }

    static SmbPath requireSmbPath(Path path) {
        if (!(requireNonNull(path) instanceof SmbPath))
            throw new ProviderMismatchException();

        return (SmbPath) path;
    }
}
