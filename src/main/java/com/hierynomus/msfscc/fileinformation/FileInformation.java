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
package com.hierynomus.msfscc.fileinformation;

import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.protocol.commons.buffer.Buffer;

public interface FileInformation {
    interface Encoder<F extends FileInformation> {
        FileInformationClass getInformationClass();

        void write(F info, Buffer outputBuffer);
    }

    interface Decoder<F extends FileInformation> {
        FileInformationClass getInformationClass();

        F read(Buffer inputBuffer) throws Buffer.BufferException;
    }

    interface Codec<F extends FileInformation> extends Encoder<F>, Decoder<F> {
    }
}
