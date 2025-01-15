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

import com.google.common.testing.EqualsTester;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class SmbPathTest {

    @Mock
    private SmbFileSystem fs;

    private SmbPath fsRoot;

    @BeforeEach
    void setUp() {
        fsRoot = SmbPath.root(fs);
    }

    @Test
    void equality() {
        new EqualsTester()
            .addEqualityGroup(SmbPath.of(fs, fsRoot, "file.txt"), SmbPath.of(fs, fsRoot, "file.txt"))
            .addEqualityGroup(SmbPath.of(fs, fsRoot, "file2.txt"), SmbPath.of(fs, fsRoot, "file2.txt"))
            .addEqualityGroup(SmbPath.of(mock(SmbFileSystem.class), fsRoot, "file.txt"))
            .addEqualityGroup(SmbPath.of(fs, null, "file.txt"))
            .testEquals();
    }

    @Test
    void calculatesPath() {

        assertEquals("\\", fsRoot.toString());

        assertEquals("\\file.txt", toPath("/file.txt").toString());
        assertEquals("\\dir", toPath("/dir").toString());
        assertEquals("\\dir\\dir2", toPath("/dir/dir2").toString());

        assertEquals("file.txt", toPath("file.txt").toString());
        assertEquals("dir", toPath("dir").toString());
        assertEquals("dir\\dir2", toPath("dir/dir2").toString());
    }

    @Test
    void normalisesAndSplitsPathComponents() {

        assertEquals("\\dir\\dir2", SmbPath.of(fs, fsRoot, "dir\\dir2").toString());
        assertEquals("\\dir\\dir2\\a\\b\\c", SmbPath.of(fs, fsRoot, "dir\\dir2", "a", "b\\c").toString());
        assertEquals("\\dir\\dir2\\a\\b\\c", SmbPath.of(fs, fsRoot, "dir/dir2", "a", "b/c").toString());
        assertEquals("\\dir\\dir2\\a\\b\\c", SmbPath.of(fs, fsRoot, "dir/dir2", "a", "b\\c").toString());
        assertEquals("\\dir\\dir2\\a\\b\\c", SmbPath.of(fs, fsRoot, "dir/dir2\\a/b\\c").toString());
    }

    @Test
    void throwsExceptionOn() {

        assertThrows(IllegalArgumentException.class, () -> SmbPath.of(fs, fsRoot, "dir\\\\d"));
    }

    @Test
    void returnsFileSystem() {
        assertSame(fs, fsRoot.getFileSystem());
        assertSame(fs, toPath("/file.txt").getFileSystem());
    }

    @Test
    void pathIsAbsolute() {

        assertFalse(fsRoot.isAbsolute());

        assertTrue(toPath("/file.txt").isAbsolute());
        assertFalse(toPath("file.txt").isAbsolute());
    }

    @Test
    void returnsRoot() {
        assertNull(fsRoot.getRoot());

        assertSame(fsRoot, toPath("/file.txt").getRoot());

        assertNull(toPath("file.txt").getRoot());
    }

    @Test
    void returnsFileName() {

        assertNull(fsRoot.getFileName());

        assertEquals("file.txt", toPath("/file.txt").getFileName().toString());
        assertEquals("c.dat", toPath("/a/b/c.dat").getFileName().toString());

        assertEquals("file.txt", toPath("file.txt").getFileName().toString());
        assertEquals("c.dat", toPath("a/b/c.dat").getFileName().toString());
    }

    @Test
    void returnsParent() {
        assertNull(fsRoot.getParent());

        assertEquals("\\", toPath("/file.txt").getParent().toString());
        assertEquals("\\a\\b", toPath("/a/b/c.dat").getParent().toString());

        assertNull(toPath("file.txt").getParent());
        assertEquals("a\\b", toPath("a/b/c.dat").getParent().toString());
    }

    @Test
    void returnsNameCount() {
        assertEquals(0, fsRoot.getNameCount());

        assertEquals(1, toPath("/file.txt").getNameCount());
        assertEquals(3, toPath("/a/b/c.dat").getNameCount());
        assertEquals(1, toPath("file.txt").getNameCount());
        assertEquals(3, toPath("a/b/c.dat").getNameCount());
    }

    @Test
    void returnsName() {
        assertEquals("file.txt", toPath("/file.txt").getName(0).toString());
        assertEquals("a", toPath("/a/b/c.dat").getName(0).toString());
        assertEquals("b", toPath("/a/b/c.dat").getName(1).toString());
        assertEquals("c.dat", toPath("/a/b/c.dat").getName(2).toString());

        assertEquals("file.txt", toPath("file.txt").getName(0).toString());
        assertEquals("a", toPath("a/b/c.dat").getName(0).toString());
        assertEquals("b", toPath("a/b/c.dat").getName(1).toString());
        assertEquals("c.dat", toPath("a/b/c.dat").getName(2).toString());
    }

    @Test
    void returnsSubpath() {
        assertEquals("file.txt", toPath("/file.txt").subpath(0, 1).toString());
        assertEquals("a", toPath("/a/b/c.dat").subpath(0, 1).toString());
        assertEquals("a\\b", toPath("/a/b/c.dat").subpath(0, 2).toString());
        assertEquals("a\\b\\c.dat", toPath("/a/b/c.dat").subpath(0, 3).toString());
        assertEquals("b", toPath("/a/b/c.dat").subpath(1, 2).toString());
        assertEquals("b\\c.dat", toPath("/a/b/c.dat").subpath(1, 3).toString());
        assertEquals("c.dat", toPath("/a/b/c.dat").subpath(2, 3).toString());

        assertEquals("file.txt", toPath("file.txt").getName(0).toString());
        assertEquals("a", toPath("a/b/c.dat").subpath(0, 1).toString());
        assertEquals("a\\b", toPath("a/b/c.dat").subpath(0, 2).toString());
        assertEquals("a\\b\\c.dat", toPath("a/b/c.dat").subpath(0, 3).toString());
        assertEquals("b", toPath("a/b/c.dat").subpath(1, 2).toString());
        assertEquals("b\\c.dat", toPath("a/b/c.dat").subpath(1, 3).toString());
        assertEquals("c.dat", toPath("a/b/c.dat").subpath(2, 3).toString());
    }

    @Test
    void resolvesPath() {
        assertEquals("\\c\\file.txt", fsRoot.resolve(toPath("/c/file.txt")).toString());
        assertEquals("\\c\\file.txt", fsRoot.resolve(toPath("c/file.txt")).toString());

        assertEquals("\\c\\file.txt", toPath("/a/b").resolve(toPath("/c/file.txt")).toString());
        assertEquals("\\a\\b\\c\\file.txt", toPath("/a/b").resolve(toPath("c/file.txt")).toString());

        assertEquals("\\c\\file.txt", toPath("a/b").resolve(toPath("/c/file.txt")).toString());
        assertEquals("a\\b\\c\\file.txt", toPath("a/b").resolve(toPath("c/file.txt")).toString());
    }

    @Test
    void factoryMethod() {
        assertEquals(SmbPath.of(fs, fsRoot, "file.txt"), toPath("/file.txt"));
        assertEquals(SmbPath.of(fs, fsRoot, "file.txt", "a"), toPath("/file.txt/a"));
        assertEquals(SmbPath.of(fs, null, "file.txt"), toPath("file.txt"));
        assertEquals(SmbPath.of(fs, null, "file.txt", "a"), toPath("file.txt/a"));
    }

    private SmbPath toPath(String path) {
        if (path.equals("/"))
            return fsRoot;

        if (path.startsWith("/"))
            return SmbPath.of(fs, fsRoot, path.substring(1));

        return SmbPath.of(fs, null, path);
    }
}
