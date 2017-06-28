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
package com.hierynomus.smbj.lock;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A simple, non-reentrant lock mechanism, which unlike {@link ReentrantLock} allows a thread to release a lock acquired
 * by a different thread.
 */
public class CrossThreadLock {
    private static final long FOREVER_MILLIS = 0xfffffffffffffffL;
    boolean isLocked = false;

    public void lock() {
        try {
            tryLock(FOREVER_MILLIS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public void unlock() {
        synchronized (this) {
            if (!isLocked) {
                throw new IllegalArgumentException("Lock is available, cannot unlock it");
            }
            isLocked = false;
            this.notify();
        }
    }

    public boolean tryLock() {
        synchronized (this) {
            if (!isLocked) {
                isLocked = true;
                return true;
            }
            return false;
        }
    }

    public boolean tryLock(long time, TimeUnit unit) throws InterruptedException {
        long millisRemaining = unit.convert(time, TimeUnit.MILLISECONDS);
        long upToTime = System.currentTimeMillis() + millisRemaining;
        while (millisRemaining > 0) {
            synchronized (this) {
                millisRemaining = upToTime - System.currentTimeMillis();
                if (millisRemaining < 0) {
                    return false; // ran out of time while waiting to synchronize
                }
                if (!isLocked) {
                    isLocked = true;
                    return true;
                }
                if (millisRemaining > 0) {
                    this.wait(millisRemaining);
                }
            }
        }
        return false;
    }
}
