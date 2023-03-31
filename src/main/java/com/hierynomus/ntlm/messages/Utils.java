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
package com.hierynomus.ntlm.messages;

import com.hierynomus.protocol.commons.buffer.Buffer;

import static com.hierynomus.ntlm.functions.NtlmFunctions.unicode;

class Utils {
    public static byte[] EMPTY = new byte[0];

    /**
     * Avoid instantiation.
     */
    private Utils() {}


    static int writeOffsettedByteArrayFields(Buffer.PlainBuffer buffer, byte[] bytes, int offset) {
        byte[] arr = bytes != null ? bytes : EMPTY;
        buffer.putUInt16(arr.length); // ArrayLen (2 bytes)
        buffer.putUInt16(arr.length); // ArrayMaxLen (2 bytes)
        buffer.putUInt32(offset); // ArrayOffset (4 bytes)
        return offset + arr.length;
    }

    static byte[] ensureNotNull(byte[] possiblyNull) {
        return possiblyNull != null ? possiblyNull : EMPTY;
    }

    static byte[] ensureNotNull(String possiblyNull) {
        return possiblyNull != null ? unicode(possiblyNull) : EMPTY;
    }
}
