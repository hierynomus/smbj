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
package com.hierynomus.msdfsc;

import static org.junit.jupiter.api.Assertions.assertLinesMatch;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class DFSPathTest {

    public static Stream<Arguments> parsedPaths() {
        return Stream.of(
                Arguments.of("\\a\\b\\c\\d", Arrays.asList("a", "b", "c", "d")),
                Arguments.of("\\\\a\\b\\c\\d", Arrays.asList("a", "b", "c", "d")),
                Arguments.of("a\\b\\c\\d", Arrays.asList("a", "b", "c", "d")),
                Arguments.of("\\a", Arrays.asList("a")),
                Arguments.of("\\a\\b", Arrays.asList("a", "b")));
    }

    @ParameterizedTest(name = "should parse {0} to components {1}")
    @MethodSource("parsedPaths")
    public void shouldParsePath(String path, List<String> components) {
        DFSPath dfsPath = new DFSPath(path);
        assertLinesMatch(components, dfsPath.getPathComponents());
    }

    @Test
    public void shouldReplacePathPrefix() {
        DFSPath dfsPath = new DFSPath("\\a\\b\\c\\d");
        DFSPath newDfsPath = dfsPath.replacePrefix("\\a\\b", "\\z\\x\\y");
        assertLinesMatch(Arrays.asList("z", "x", "y", "c", "d"), newDfsPath.getPathComponents());
    }
}
