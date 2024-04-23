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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    void calculatesPath() {

        assertEquals("\\", fsRoot.toString());

        assertEquals("\\file.txt", SmbPath.of(fs, fsRoot, "file.txt").toString());
        assertEquals("\\dir", SmbPath.of(fs, fsRoot, "dir").toString());
        assertEquals("\\dir\\dir2", SmbPath.of(fs, fsRoot, "dir", "dir2").toString());

        assertEquals("file.txt", SmbPath.of(fs, null, "file.txt").toString());
        assertEquals("dir", SmbPath.of(fs, null, "dir").toString());
        assertEquals("dir\\dir2", SmbPath.of(fs, null, "dir", "dir2").toString());
    }

    @Test
    void returnsFileSystem() {
        assertSame(fs, fsRoot.getFileSystem());
        assertSame(fs, SmbPath.of(fs, fsRoot, "file.txt").getFileSystem());
    }

    @Test
    void pathIsAbsolute() {

        assertFalse(fsRoot.isAbsolute());

        assertTrue(SmbPath.of(fs, fsRoot, "file.txt").isAbsolute());
        assertFalse(SmbPath.of(fs, null, "file.txt").isAbsolute());
    }

    @Test
    void returnsRoot() {
        assertNull(fsRoot.getRoot());

        assertSame(fsRoot, SmbPath.of(fs, fsRoot, "file.txt").getRoot());

        assertNull(SmbPath.of(fs, null, "file.txt").getRoot());
    }

    @Test
    void returnsFileName() {

        assertNull(fsRoot.getFileName());

        assertEquals("file.txt", SmbPath.of(fs, fsRoot, "file.txt").getFileName().toString());
        assertEquals("c.dat", SmbPath.of(fs, fsRoot, "a", "b", "c.dat").getFileName().toString());

        assertEquals("file.txt", SmbPath.of(fs, null, "file.txt").getFileName().toString());
        assertEquals("c.dat", SmbPath.of(fs, null, "a", "b", "c.dat").getFileName().toString());
    }

    @Test
    void returnsParent() {
        assertNull(fsRoot.getParent());

        assertEquals("\\", SmbPath.of(fs, fsRoot, "file.txt").getParent().toString());
        assertEquals("\\a\\b", SmbPath.of(fs, fsRoot, "a", "b", "c.dat").getParent().toString());

        assertNull(SmbPath.of(fs, null, "file.txt").getParent());
        assertEquals("a\\b", SmbPath.of(fs, null, "a", "b", "c.dat").getParent().toString());
    }

    @Test
    void returnsNameCount() {
        assertEquals(0, fsRoot.getNameCount());

        assertEquals(1, SmbPath.of(fs, fsRoot, "file.txt").getNameCount());
        assertEquals(3, SmbPath.of(fs, fsRoot, "a", "b", "c.dat").getNameCount());
        assertEquals(1, SmbPath.of(fs, null, "file.txt").getNameCount());
        assertEquals(3, SmbPath.of(fs, null, "a", "b", "c.dat").getNameCount());
    }

    @Test
    void returnsName() {
        assertEquals("file.txt", SmbPath.of(fs, fsRoot, "file.txt").getName(0).toString());
        assertEquals("a", SmbPath.of(fs, fsRoot, "a", "b", "c.dat").getName(0).toString());
        assertEquals("b", SmbPath.of(fs, fsRoot, "a", "b", "c.dat").getName(1).toString());
        assertEquals("c.dat", SmbPath.of(fs, fsRoot, "a", "b", "c.dat").getName(2).toString());

        assertEquals("file.txt", SmbPath.of(fs, null, "file.txt").getName(0).toString());
        assertEquals("a", SmbPath.of(fs, null, "a", "b", "c.dat").getName(0).toString());
        assertEquals("b", SmbPath.of(fs, null, "a", "b", "c.dat").getName(1).toString());
        assertEquals("c.dat", SmbPath.of(fs, null, "a", "b", "c.dat").getName(2).toString());
    }

    @Test
    void returnsSubpath() {
        assertEquals("file.txt", SmbPath.of(fs, fsRoot, "file.txt").subpath(0, 1).toString());
        assertEquals("a", SmbPath.of(fs, fsRoot, "a", "b", "c.dat").subpath(0, 1).toString());
        assertEquals("a\\b", SmbPath.of(fs, fsRoot, "a", "b", "c.dat").subpath(0, 2).toString());
        assertEquals("a\\b\\c.dat", SmbPath.of(fs, fsRoot, "a", "b", "c.dat").subpath(0, 3).toString());
        assertEquals("b", SmbPath.of(fs, fsRoot, "a", "b", "c.dat").subpath(1, 2).toString());
        assertEquals("b\\c.dat", SmbPath.of(fs, fsRoot, "a", "b", "c.dat").subpath(1, 3).toString());
        assertEquals("c.dat", SmbPath.of(fs, fsRoot, "a", "b", "c.dat").subpath(2, 3).toString());

        assertEquals("file.txt", SmbPath.of(fs, null, "file.txt").getName(0).toString());
        assertEquals("a", SmbPath.of(fs, null, "a", "b", "c.dat").subpath(0, 1).toString());
        assertEquals("a\\b", SmbPath.of(fs, null, "a", "b", "c.dat").subpath(0, 2).toString());
        assertEquals("a\\b\\c.dat", SmbPath.of(fs, null, "a", "b", "c.dat").subpath(0, 3).toString());
        assertEquals("b", SmbPath.of(fs, null, "a", "b", "c.dat").subpath(1, 2).toString());
        assertEquals("b\\c.dat", SmbPath.of(fs, null, "a", "b", "c.dat").subpath(1, 3).toString());
        assertEquals("c.dat", SmbPath.of(fs, null, "a", "b", "c.dat").subpath(2, 3).toString());
    }
    
    @Test
    void resolvesPath() {
        assertEquals("\\c\\file.txt", fsRoot.resolve(SmbPath.of(fs, fsRoot, "c", "file.txt")).toString());
        assertEquals("\\c\\file.txt", fsRoot.resolve(SmbPath.of(fs, null, "c", "file.txt")).toString());

        assertEquals("\\c\\file.txt", SmbPath.of(fs, fsRoot, "a", "b").resolve(SmbPath.of(fs, fsRoot, "c", "file.txt")).toString());
        assertEquals("\\a\\b\\c\\file.txt", SmbPath.of(fs, fsRoot, "a", "b").resolve(SmbPath.of(fs, null, "c", "file.txt")).toString());

        assertEquals("\\c\\file.txt", SmbPath.of(fs, null, "a", "b").resolve(SmbPath.of(fs, fsRoot, "c", "file.txt")).toString());
        assertEquals("a\\b\\c\\file.txt", SmbPath.of(fs, null, "a", "b").resolve(SmbPath.of(fs, null, "c", "file.txt")).toString());
    }
}
