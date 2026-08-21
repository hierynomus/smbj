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
import com.hierynomus.smbj.share.DiskShare;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SmbFileSystemTest {

    @Mock
    private SmbFileSystemProvider provider;

    @Mock
    private ShareSource shares;

    private SmbFileSystem fileSystem;

    @BeforeEach
    void setUp() {
        fileSystem = new SmbFileSystem(provider, shares, "theShare");
    }

    @Test
    void isOpenByDefault() {
        assertTrue(fileSystem.isOpen());
    }

    @Test
    void closesAndRemovesFromProvider() throws Exception {

        assertTrue(fileSystem.isOpen());
        fileSystem.close();

        assertFalse(fileSystem.isOpen());

        InOrder o = inOrder(provider, shares);
        o.verify(provider).removeFileSystem(fileSystem);
        o.verify(shares).close();
        o.verifyNoMoreInteractions();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "/",
        "\\"
    })
    void rootPaths(String first) {

        assertEquals(fileSystem.root(), fileSystem.getPath(first));
    }

    static Stream<Arguments> absolutePaths() {
        return Stream.of(
            arguments("\\dir\\dir2", rest(), List.of("dir", "dir2")),
            arguments("/dir\\dir2", rest("a", "b\\c"), List.of("dir", "dir2", "a", "b", "c")),
            arguments("\\dir/dir2", rest("a", "b/c"), List.of("dir", "dir2", "a", "b", "c")),
            arguments("/dir/dir2", rest("a", "b\\c"), List.of("dir", "dir2", "a", "b", "c")),
            arguments("/dir/dir2\\a/b\\c", rest(), List.of("dir", "dir2", "a", "b", "c"))
        );
    }

    @ParameterizedTest
    @MethodSource("absolutePaths")
    void getsAbsolutePath(String first, String[] rest, List<String> elements) {

        assertEquals(SmbPath.of(fileSystem, fileSystem.root(), elements), fileSystem.getPath(first, rest));
    }

    static Stream<Arguments> relativePaths() {
        return Stream.of(
            arguments("dir\\dir2", rest(), List.of("dir", "dir2")),
            arguments("dir\\dir2", rest("a", "b\\c"), List.of("dir", "dir2", "a", "b", "c")),
            arguments("dir/dir2", rest("a", "b/c"), List.of("dir", "dir2", "a", "b", "c")),
            arguments("dir/dir2", rest("a", "b\\c"), List.of("dir", "dir2", "a", "b", "c")),
            arguments("dir/dir2\\a/b\\c", rest(), List.of("dir", "dir2", "a", "b", "c"))
        );
    }

    @ParameterizedTest
    @MethodSource("relativePaths")
    void getsRelativePath(String first, String[] rest, List<String> elements) {

        assertEquals(SmbPath.of(fileSystem, null, elements), fileSystem.getPath(first, rest));
    }

    private static String[] rest(String... elements) {
        return elements;
    }

    @Nested
    class AccessMaskTests {

        @Mock
        private DiskShare diskShare;

        @Mock
        private com.hierynomus.smbj.share.File smbFile;

        @Captor
        private ArgumentCaptor<Set<AccessMask>> accessMaskCaptor;

        @BeforeEach
        void setUp() throws Exception {
            when(shares.getShare("theShare")).thenReturn(diskShare);
            when(diskShare.openFile(any(), accessMaskCaptor.capture(), any(), any(), any(), any()))
                .thenReturn(smbFile);
        }

        @Test
        void appendOnlyProducesFileAppendData() throws Exception {
            when(smbFile.getLength()).thenReturn(0L);
            fileSystem.newByteChannel(fileSystem.getPath("test.txt"),
                EnumSet.of(StandardOpenOption.APPEND, StandardOpenOption.CREATE), new FileAttribute[0]);

            Set<AccessMask> masks = accessMaskCaptor.getValue();
            assertTrue(masks.contains(AccessMask.FILE_APPEND_DATA));
            assertFalse(masks.contains(AccessMask.FILE_WRITE_DATA));
            assertFalse(masks.contains(AccessMask.FILE_READ_DATA));
        }

        @Test
        void writeOnlyProducesFileWriteData() throws Exception {
            fileSystem.newByteChannel(fileSystem.getPath("test.txt"),
                EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE), new FileAttribute[0]);

            Set<AccessMask> masks = accessMaskCaptor.getValue();
            assertTrue(masks.contains(AccessMask.FILE_WRITE_DATA));
            assertFalse(masks.contains(AccessMask.FILE_APPEND_DATA));
            assertFalse(masks.contains(AccessMask.FILE_READ_DATA));
        }

        @Test
        void readOnlyProducesFileReadData() throws Exception {
            fileSystem.newByteChannel(fileSystem.getPath("test.txt"),
                EnumSet.of(StandardOpenOption.READ), new FileAttribute[0]);

            Set<AccessMask> masks = accessMaskCaptor.getValue();
            assertTrue(masks.contains(AccessMask.FILE_READ_DATA));
            assertFalse(masks.contains(AccessMask.FILE_WRITE_DATA));
            assertFalse(masks.contains(AccessMask.FILE_APPEND_DATA));
        }
    }
}
