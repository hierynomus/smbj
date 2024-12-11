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
