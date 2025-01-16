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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class SmbPathTest {

    private final SmbFileSystem fs = new SmbFileSystem(null, null, null);

    private SmbPath fsRoot;

    @BeforeEach
    void setUp() {
        fsRoot = fs.root();
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
    void parses() {

        assertEquals("\\dir\\dir2", SmbPath.of(fs, fsRoot, "dir\\dir2").toString());
        assertEquals("\\dir\\dir2\\a\\b\\c", SmbPath.of(fs, fsRoot, "dir\\dir2\\a\\b\\c").toString());
    }

    @Test
    void throwsExceptionOn() {

        assertThrows(IllegalArgumentException.class, () -> SmbPath.of(fs, fsRoot, List.of("asd", "", "dsfdsf")));
    }

    @Test
    void throwsExceptionOnNoElements() {

        assertThrows(IllegalArgumentException.class, () -> SmbPath.of(fs, fsRoot, List.of()));
    }

    @ParameterizedTest
    @CsvSource({
        "/",
        "/file.txt",
    })
    void returnsFileSystem(String path) {

        assertSame(fs, toPath(path).getFileSystem());
    }

    @ParameterizedTest
    @CsvSource({
        "/,false",
        "/file.txt,true",
        "file.txt,false",
    })
    void pathIsAbsolute(String path, boolean absolute) {

        assertEquals(absolute, toPath(path).isAbsolute());
    }

    @Test
    void returnsRoot() {
        assertNull(fsRoot.getRoot());

        assertSame(fsRoot, toPath("/file.txt").getRoot());

        assertNull(toPath("file.txt").getRoot());
    }

    @ParameterizedTest
    @CsvSource({
        "/,",
        "/file.txt,file.txt",
        "/a/b/c.dat,c.dat",
        "file.txt,file.txt",
        "a/b/c.dat,c.dat",
    })
    void returnsFileName(String path, String fileName) {

        assertEquals(toPath(fileName), toPath(path).getFileName());
    }

    @ParameterizedTest
    @CsvSource({
        "/,",
        "/file.txt,/",
        "/a/b/c.dat,/a/b",
        "file.txt,",
        "a/b/c.dat,a/b",
    })
    void returnsParent(String path, String parent) {

        assertEquals(toPath(parent), toPath(path).getParent());
    }

    @ParameterizedTest
    @CsvSource({
        "/,0",
        "/file.txt,1",
        "/a/b/c.dat,3",
        "file.txt,1",
        "a/b/c.dat,3",
    })
    void returnsNameCount(String path, int nameCount) {

        assertEquals(nameCount, toPath(path).getNameCount());
    }

    @ParameterizedTest
    @CsvSource({
        "/file.txt,0,file.txt",
        "/a/b/c.dat,0,a",
        "/a/b/c.dat,1,b",
        "/a/b/c.dat,2,c.dat",
        "file.txt,0,file.txt",
        "a/b/c.dat,0,a",
        "a/b/c.dat,1,b",
        "a/b/c.dat,2,c.dat",
    })
    void returnsName(String path, int nameIndex, String name) {

        assertEquals(toPath(name), toPath(path).getName(nameIndex));
    }

    @ParameterizedTest
    @CsvSource({
        "/file.txt,0,1,file.txt",
        "/a/b/c.dat,0,1,a",
        "/a/b/c.dat,0,2,a/b",
        "/a/b/c.dat,0,3,a/b/c.dat",
        "/a/b/c.dat,1,2,b",
        "/a/b/c.dat,1,3,b/c.dat",
        "/a/b/c.dat,2,3,c.dat",
        "file.txt,0,1,file.txt",
        "a/b/c.dat,0,1,a",
        "a/b/c.dat,0,2,a/b",
        "a/b/c.dat,0,3,a/b/c.dat",
        "a/b/c.dat,1,2,b",
        "a/b/c.dat,1,3,b/c.dat",
        "a/b/c.dat,2,3,c.dat",
    })
    void returnsSubpath(String path, int startIndex, int endIndex, String subpath) {

        assertEquals(toPath(subpath), toPath(path).subpath(startIndex, endIndex));
    }

    @ParameterizedTest
    @CsvSource({
        "/,/c/file.txt,/c/file.txt",
        "/,c/file.txt,/c/file.txt",
        "/a/b,/c/file.txt,/c/file.txt",
        "/a/b,c/file.txt,/a/b/c/file.txt",
        "a/b,/c/file.txt,/c/file.txt",
        "a/b,c/file.txt,a/b/c/file.txt",
    })
    void resolvesPath(String basePath, String newPath, String resolvedPath) {

        assertEquals(toPath(resolvedPath), toPath(basePath).resolve(toPath(newPath)));
    }

    @ParameterizedTest
    @CsvSource({
        "/,/c/file.txt,/c/file.txt",
        "/,c/file.txt,c/file.txt",
        "/a/b,/c/file.txt,/c/file.txt",
        "/a/b,c/file.txt,/a/c/file.txt",
        "a/b,/c/file.txt,/c/file.txt",
        "a/b,c/file.txt,a/c/file.txt",
    })
    void resolvesSiblings(String basePath, String newPath, String resolvedPath) {

        assertEquals(toPath(resolvedPath), toPath(basePath).resolveSibling(toPath(newPath)));
    }

    private SmbPath toPath(String path) {
        if (path == null)
            return null;

        return fs.getPath(path);
    }
}
