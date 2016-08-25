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
package com.hierynomus.mssmb2;

public class SMB2MultiCreditPacket extends SMB2Packet {

    protected int creditsAssigned = 1;
    private int creditsNeeded;
    private int payloadSize;

    public SMB2MultiCreditPacket(int structureSize, SMB2Dialect dialect, SMB2MessageCommandCode messageType, long sessionId, long treeId, int payloadSize) {
        super(structureSize, dialect, messageType, sessionId, treeId);
        this.payloadSize = payloadSize;
    }

    public int getPayloadSize() {
        return this.payloadSize;
    }

    public void setCreditsAssigned(int creditsAssigned) {
        this.creditsAssigned = creditsAssigned;
        getHeader().setCreditCharge(creditsAssigned);
    }
}
