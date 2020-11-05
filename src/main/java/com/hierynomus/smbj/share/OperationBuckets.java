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
package com.hierynomus.smbj.share;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import com.hierynomus.smbj.common.SMBRuntimeException;

class OperationBuckets {
    private List<OperationBucket> buckets = new ArrayList<>();
    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    OperationBucket takeFreeBucket() {
        lock.writeLock().lock();
        try {
            for (OperationBucket bucket : buckets) {
                if (bucket.free) {
                    bucket.free = false;
                    return bucket;
                }
            }

            // Max 64 buckets exist
            if (buckets.size() < 64) {
                OperationBucket bucket = new OperationBucket(buckets.size() + 1);
                buckets.add(bucket);
                return bucket;
            }

            throw new SMBRuntimeException("No OperationBucket found which is free");
        } finally {
            lock.writeLock().unlock();
        }
    }

    void freeBucket(int index) {
        lock.writeLock().lock();
        try {
            OperationBucket bucket = buckets.get(index - 1);
            bucket.free = true;
            bucket.sequenceNumber += 1 % 16;
        } finally {
            lock.writeLock().unlock();
        }
    }

    class OperationBucket {
        private boolean free;
        private final int index;
        private short sequenceNumber;

        OperationBucket(int index) {
            this.free = false;
            this.index = index;
            this.sequenceNumber = 0;
        }

        public int getIndex() {
            return index;
        }

        short getSequenceNumber() {
            return sequenceNumber;
        }
    }
}
