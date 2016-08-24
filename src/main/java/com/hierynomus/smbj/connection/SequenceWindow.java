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

import com.hierynomus.smbj.common.SMBRuntimeException;

import java.io.Serializable;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicLong;

/**
 * [MS-SMB2].pdf 3.2.4.1.6 Algorithm for Handling Available Message Sequence Numbers by the Client.
 * <p/>
 * The client MUST implement an algorithm to manage message sequence numbers.
 * <p/>
 * Sequence numbers are used to associate requests with responses and to determine what requests are allowed for processing.
 * The algorithm MUST meet the following conditions:
 * <ul>
 * <li>When the connection is first established, the allowable sequence numbers for sending a request MUST be set to the set { 0 }.</li>
 * <li>The client MUST never send a request on a given connection with a sequence number that has already been used unless it is a request to cancel a previously sent request.</li>
 * <li>The client MUST grow the set in a monotonically increasing manner based on the credits granted. If the set is { 0 }, and 2 credits are granted, the set MUST grow to { 0, 1, 2 }.</li>
 * <li>The client MUST use the lowest available sequence number in its allowable set for each request.</li>
 * <li>For a multi-credit request as specified in section 3.2.4.1.5, the client MUST use the lowest available range of consecutive sequence numbers.</li>
 * </ul>
 */
class SequenceWindow {
    static final int PREFERRED_MINIMUM_CREDITS = 512;
    private AtomicLong lowestAvailable = new AtomicLong(0);
    private Semaphore available = new Semaphore(1);

    long get() {
        if (available.tryAcquire()) {
            return lowestAvailable.getAndIncrement();
        }
        throw new SMBRuntimeException("No more credits available to hand out sequence number");
    }

    long[] get(int credits) {
        if (available.tryAcquire(credits)) {
            long lowest = lowestAvailable.getAndAdd(credits);
            return range(lowest, lowest + credits);
        }
        throw new SMBRuntimeException("Not enough credits (" + available.availablePermits() + " available) to hand out " + credits + " sequence numbers");
    }

    void disableCredits() {
        this.available = new NoopSemaphore();
    }

    int available() {
        return available.availablePermits();
    }

    void creditsGranted(int credits) {
        available.release(credits);
    }

    private long[] range(long start, long stop) {
        int l = (int) (stop - start);
        long[] result = new long[l];

        for (int i = 0; i < l; i++)
            result[i] = start + i;

        return result;
    }

    private static class NoopSemaphore extends Semaphore {
        public NoopSemaphore() {
            super(1);
        }

        @Override
        public boolean tryAcquire() {
            return true;
        }

        @Override
        public boolean tryAcquire(int permits) {
            return true;
        }

        @Override
        public void release(int permits) {
            // no-op
        }

        @Override
        public int availablePermits() {
            return Integer.MAX_VALUE;
        }
    }

    public static class Range implements Serializable, Iterable<Long> {
        long minInclusive;
        long maxExclusive;

        public Range(long minInclusive, long maxExclusive) {
            this.minInclusive = minInclusive;
            this.maxExclusive = maxExclusive;
        }

        @Override
        public Iterator<Long> iterator() {
            return new Iterator<Long>() {
                long current = minInclusive;

                @Override
                public boolean hasNext() {
                    return current < maxExclusive;
                }

                @Override
                public Long next() {
                    if (current >= maxExclusive) {
                        throw new NoSuchElementException("Range Iterator depleted");
                    }
                    return current++;
                }

                @Override
                public void remove() {
                    throw new UnsupportedOperationException();
                }
            };
        }
    }
}
