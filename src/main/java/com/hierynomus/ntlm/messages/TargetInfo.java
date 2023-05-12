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

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.ntlm.av.AvId;
import com.hierynomus.ntlm.av.AvPair;
import com.hierynomus.ntlm.av.AvPairEnd;
import com.hierynomus.ntlm.av.AvPairFactory;
import com.hierynomus.protocol.commons.buffer.Buffer;

public class TargetInfo {
    private static final Logger logger = LoggerFactory.getLogger(TargetInfo.class);

    private List<AvPair<?>> targetInfo = new ArrayList<>();

    public TargetInfo() {}

    public TargetInfo readFrom(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        while (true) {
            AvPair<?> p = AvPairFactory.read(buffer);
            if (p.getAvId() == AvId.MsvAvEOL) {
                break;
            }
            logger.trace("Read TargetInfo {} --> {}", p.getAvId(), p.getValue());
            targetInfo.add(p);
        }

        return this;
    }

    public void writeTo(Buffer.PlainBuffer buffer) {
        for (AvPair<?> pair : targetInfo) {
            logger.trace("Writing TargetInfo {} --> {}", pair.getAvId(), pair.getValue());
            pair.write(buffer);
        }
        new AvPairEnd().write(buffer);
    }

    public TargetInfo copy() {
        TargetInfo c = new TargetInfo();
        c.targetInfo = new ArrayList<>(targetInfo);
        return c;
    }

    @SuppressWarnings("unchecked")
    public <T extends AvPair<?>> T getAvPair(AvId key) {
        for (AvPair<?> avPair : targetInfo) {
            if (avPair.getAvId() == key) {
                return (T) avPair;
            }
        }
        return null;
    }

    public void putAvPair(AvPair<?> pair) {
        for (AvPair<?> avPair : targetInfo) {
            if (avPair.getAvId() == pair.getAvId()) {
                targetInfo.remove(avPair);
                break;
            }
        }
        this.targetInfo.add(pair);
    }

    public boolean hasAvPair(AvId key) {
        for (AvPair<?> avPair : targetInfo) {
            if (avPair.getAvId() == key) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String toString() {
        return "TargetInfo{" +
            "targetInfo=" + targetInfo +
            '}';
    }
}
