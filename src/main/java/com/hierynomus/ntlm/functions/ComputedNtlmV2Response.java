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
package com.hierynomus.ntlm.functions;

public class ComputedNtlmV2Response {
    private byte[] ntResponse;
    private byte[] lmResponse;
    private byte[] sessionBaseKey;

    public ComputedNtlmV2Response(byte[] ntResponse, byte[] lmResponse, byte[] sessionBaseKey) {
        this.ntResponse = ntResponse;
        this.lmResponse = lmResponse;
        this.sessionBaseKey = sessionBaseKey;
    }

    public byte[] getNtResponse() {
        return ntResponse;
    }

    public byte[] getLmResponse() {
        return lmResponse;
    }

    public byte[] getSessionBaseKey() {
        return sessionBaseKey;
    }
}
