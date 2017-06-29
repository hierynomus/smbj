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

import static org.junit.Assert.assertNotEquals;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class CrossThreadLockTest {
    private static int numTestThreads = Integer.parseInt(System.getProperty("numThreads", "10"));
    private static long testTimeMillis = Long.parseLong(System.getProperty("testTimeMillis", "2000"));
    private static long postTestUnlockTimeMillis = Long.parseLong(System.getProperty("postTestUnlockTimeMillis", "50"));
    private static long millisToWaitForCrossThreadLock = Long.parseLong(System.getProperty("millisToWaitForCrossThreadLock", "5"));

    private long testEndTimeMillis;
    private LockingAndReleasing[] testThreads = new LockingAndReleasing[numTestThreads];
    private CrossThreadLock lock;

    private static final int NOBODY = -1;
    private AtomicInteger whoShouldRelease = new AtomicInteger(NOBODY);
    private AtomicLong timeOfLastLock = new AtomicLong();
    private CountDownLatch testEndLatch;

    @Before
    public void setUp() {
        lock = new CrossThreadLock();
        testEndTimeMillis = System.currentTimeMillis() + testTimeMillis;
        testEndLatch = new CountDownLatch(numTestThreads);
    }

    @Test
    public void manyIndependentThreadsShouldNotHangOrStarve() throws InterruptedException {
        for (int i = 0; i < numTestThreads; ++i) {
            testThreads[i] = new LockingAndReleasing(i);
        }
        runTestThreadsAndWait();
        assetAllThreadsLocked();
    }

    @Test
    public void crossDependentThreadsShouldNotHangOrStarve() throws InterruptedException {
        for (int i = 0; i < numTestThreads; ++i) {
            testThreads[i] = new LockingAndAskingAnotherToRelease(i);
        }
        runTestThreadsAndWait();
//        printStatus();
        assertRecentLock();
        assetAllThreadsLocked();
    }

    private void runTestThreadsAndWait() throws InterruptedException {
        for (int i = 0; i < numTestThreads; ++i) {
            testThreads[i].start();
        }
        testEndLatch.await();
    }

    private void assertRecentLock() {
        long shouldHaveLockedAfter = System.currentTimeMillis() - 1000L;
        Assert.assertTrue(timeOfLastLock.get() > shouldHaveLockedAfter);

    }

    private void assetAllThreadsLocked() {
        for (int i = 0; i < numTestThreads; ++i) {
            assertNotEquals(0, testThreads[i].counter.get());
        }
    }

    protected void printStatus() {
        System.out.println("Who should release: " + this.whoShouldRelease);
        for (int i = 0; i < numTestThreads; ++i) {
            String fmt = "Thread %d (%s): running=%b count=%d";
            LockingAndReleasing thread = testThreads[i];
            System.out.println(String.format(fmt, i, thread.getName(), thread.isAlive(), thread.counter.get()));
        }
    }

    private class LockingAndReleasing extends Thread {
        protected final AtomicInteger counter = new AtomicInteger();

        private LockingAndReleasing(int myNumber) {
            super.setName("#" + myNumber);
        }
        
        @Override
        public void run() {
            try {
                doLoop();
            } catch (InterruptedException e) {
                throw new IllegalStateException(e);
            } finally {
                testEndLatch.countDown();
            }
        }

        protected void doLoop() throws InterruptedException {
            while (System.currentTimeMillis() < testEndTimeMillis) {
                lock.lock();
                counter.incrementAndGet();
                lock.unlock();
            }
        }
    }

    private class LockingAndAskingAnotherToRelease extends LockingAndReleasing {
        private final int myNumber;

        private LockingAndAskingAnotherToRelease(int myNumber) {
            super(myNumber);
            this.myNumber = myNumber;
        }

        @Override
        protected void doLoop() throws InterruptedException {
            while (System.currentTimeMillis() < testEndTimeMillis) {
                unlockIfAsked();
                boolean gotLock = lock.tryLock(millisToWaitForCrossThreadLock, TimeUnit.MILLISECONDS);
                if (gotLock) {
                    int randomThreadNumber = (int) (Math.random() * numTestThreads);
                    counter.incrementAndGet();
                    timeOfLastLock.set(System.currentTimeMillis());
                    whoShouldRelease.set(randomThreadNumber);
                }
            }
            while (System.currentTimeMillis() < testEndTimeMillis + postTestUnlockTimeMillis) {
                unlockIfAsked();
            }
        }

        private void unlockIfAsked() {
            if (whoShouldRelease.get() == myNumber) {
                whoShouldRelease.set(NOBODY);
                lock.unlock();
            }
        }
    }
}
