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
package com.hierynomus.smbj.connection;

import com.hierynomus.mssmb2.SMB2Dialect;

import static com.hierynomus.mssmb2.SMB2Packet.SINGLE_CREDIT_PAYLOAD_SIZE;

/**
 * Encapsulates the details of the Protocol Negotiation
 */
public class NegotiatedProtocol {
    private SMB2Dialect dialect;
    private int maxTransactSize;
    private int maxReadSize;
    private int maxWriteSize;

    public NegotiatedProtocol(SMB2Dialect dialect, int maxTransactSize, int maxReadSize, int maxWriteSize, boolean supportsMultiCredit) {
        this.dialect = dialect;
        this.maxTransactSize = supportsMultiCredit ? maxTransactSize : Math.max(maxTransactSize, SINGLE_CREDIT_PAYLOAD_SIZE);
        this.maxReadSize = supportsMultiCredit ? maxReadSize : Math.max(maxReadSize, SINGLE_CREDIT_PAYLOAD_SIZE);
        this.maxWriteSize = supportsMultiCredit ? maxWriteSize : Math.max(maxWriteSize, SINGLE_CREDIT_PAYLOAD_SIZE);
    }

    public SMB2Dialect getDialect() {
        return dialect;
    }

    public int getMaxTransactSize() {
        return maxTransactSize;
    }

    public int getMaxReadSize() {
        return maxReadSize;
    }

    public int getMaxWriteSize() {
        return maxWriteSize;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("NegotiatedProtocol{");
        sb.append("dialect=").append(dialect);
        sb.append(", maxTransactSize=").append(maxTransactSize);
        sb.append(", maxReadSize=").append(maxReadSize);
        sb.append(", maxWriteSize=").append(maxWriteSize);
        sb.append('}');
        return sb.toString();
    }
}
