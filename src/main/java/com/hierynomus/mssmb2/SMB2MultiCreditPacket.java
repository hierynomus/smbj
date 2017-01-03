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

    private int maxPayloadSize;

    public SMB2MultiCreditPacket(int structureSize, SMB2Dialect dialect, SMB2MessageCommandCode messageType, long sessionId, long treeId, int maxPayloadSize) {
        super(structureSize, dialect, messageType, sessionId, treeId);
        this.maxPayloadSize = maxPayloadSize;
    }

    public int getMaxPayloadSize() {
        return this.maxPayloadSize;
    }

    public int getPayloadSize() {
        return Math.min(maxPayloadSize, SINGLE_CREDIT_PAYLOAD_SIZE * getCreditsAssigned());
    }

    public int getCreditsAssigned() {
        return getHeader().getCreditCharge();
    }
    public void setCreditsAssigned(int creditsAssigned) {
        getHeader().setCreditCharge(creditsAssigned);
    }
}
