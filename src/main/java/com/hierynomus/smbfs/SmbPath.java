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
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.IntStream;

import static com.hierynomus.smbfs.ToBeImplementedException.toBeImplemented;

public class SmbPath implements Path {

    public static final char SEPARATOR = '\\';

    private final SmbFileSystem fileSystem;

    private final SmbPath root;
    private final List<String> elements;

    private SmbPath(SmbFileSystem fileSystem, SmbPath root, List<String> elements) {
        this.fileSystem = fileSystem;
        this.root = root;
        this.elements = elements;
    }

    @Override
    public SmbFileSystem getFileSystem() {
        return fileSystem;
    }

    @Override
    public boolean isAbsolute() {
        return root != null;
    }

    @Override
    public SmbPath getRoot() {
        return root;
    }

    @Override
    public SmbPath getFileName() {
        if (elements != null) {
            int size = elements.size();
            return withRelative(elements.subList(size - 1, size));
        }

        return null;
    }

    @Override
    public SmbPath getParent() {
        if (elements != null && elements.size() > 1)
            return withAbsolute(elements.subList(0, elements.size() - 1));

        return root;
    }

    @Override
    public int getNameCount() {
        if (elements != null)
            return elements.size();

        return 0;
    }

    @Override
    public SmbPath getName(int index) {
        if (elements == null)
            throw new IllegalArgumentException();
        if (index < 0)
            throw new IllegalArgumentException();
        if (index >= elements.size())
            throw new IllegalArgumentException();

        return withRelative(elements.subList(index, index + 1));
    }

    @Override
    public SmbPath subpath(int beginIndex, int endIndex) {
        if (elements == null)
            throw new IllegalArgumentException();
        if (beginIndex < 0 || beginIndex >= elements.size())
            throw new IllegalArgumentException("beginIndex");
        if (endIndex <= beginIndex || endIndex > elements.size())
            throw new IllegalArgumentException("endIndex");

        return withRelative(elements.subList(beginIndex, endIndex));
    }

    @Override
    public boolean startsWith(Path path) {
        throw toBeImplemented();
    }

    @Override
    public boolean startsWith(String other) {
        throw toBeImplemented();
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
    public SmbPath resolve(Path other) {
        throw toBeImplemented();
    }

    @Override
    public SmbPath resolve(String other) {
        throw toBeImplemented();
    }

    @Override
    public SmbPath resolveSibling(Path other) {
        throw toBeImplemented();
    }

    @Override
    public SmbPath resolveSibling(String other) {
        throw toBeImplemented();
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
        if (root != null)
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
        return IntStream.range(0, elements.size() -1)
            .mapToObj(i -> (Path)getName(i))
            .iterator();
    }

    @Override
    public String toString() {
        if (elements == null)
            return "" + SEPARATOR;

        StringBuilder b = new StringBuilder();

        if (isAbsolute())
            b.append(SEPARATOR);

        for (int i = 0; i < elements.size(); i++) {
            if (i > 0) b.append(SEPARATOR);

            b.append(elements.get(i));
        }

        return b.toString();
    }

    private SmbPath withRelative(List<String> elements) {
        return of(fileSystem, null, elements);
    }

    private SmbPath withAbsolute(List<String> elements) {
        return of(fileSystem, root, elements);
    }

    static SmbPath root(SmbFileSystem smbFileSystem) {
        return new SmbPath(smbFileSystem, null, null);
    }

    static SmbPath of(SmbFileSystem fileSystem, SmbPath rootPath, List<String> elements) {
        if (elements.isEmpty())
            throw new IllegalArgumentException();

        return new SmbPath(fileSystem, rootPath, elements);
    }

    static SmbPath of(SmbFileSystem fileSystem, SmbPath rootPath, String first, String... more) {
        List<String> elements = new ArrayList<>();
        elements.add(first);
        elements.addAll(Arrays.asList(more));

        return of(fileSystem, rootPath, elements);
    }
}
