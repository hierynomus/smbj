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
package com.hierynomus.spnego;

import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.protocol.commons.buffer.Buffer;

public class RawToken extends SpnegoToken {
    private byte[] rawToken;

    public RawToken(byte[] rawToken) {
        super(0, null);
        this.rawToken = rawToken;
    }

    @Override
    protected void parseTagged(ASN1TaggedObject asn1TaggedObject) throws SpnegoException {
        throw new UnsupportedOperationException("RawToken does not support parsing of tagged objects");
    }

    @Override
    public void write(Buffer<?> buffer) throws SpnegoException {
        if (rawToken != null) {
            buffer.putRawBytes(rawToken);
        }
    }
}
