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
package com.hierynomus.smbj.io;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.junit.jupiter.api.Test;

public class BufferedInputStreamReaderTest {
    private static final int EOF = -1;

    @Test
    void shouldReturnIsAvailableFalseWhenUnderlyingInputStreamSignalsEOF() throws IOException {
        BufferedInputStreamReader bufferedInputStreamReader = new BufferedInputStreamReader(
            new BufferedInputStream(
                new ByteArrayInputStream(new byte[] {1, 2, 3})
            ));

        assertThat(bufferedInputStreamReader.isAvailable()).isTrue();

        byte[] outputArray = new byte[3];
        assertThat(bufferedInputStreamReader.read(outputArray, 0, 3)).isEqualTo(3);

        // Still some bytes might be read
        assertThat(bufferedInputStreamReader.isAvailable()).isTrue();

        assertThat(bufferedInputStreamReader.read(new byte[100], 0, 100)).isEqualTo(EOF);
        assertThat(bufferedInputStreamReader.isAvailable()).isFalse();
    }

}
