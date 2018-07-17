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
package com.hierynomus.protocol.commons.concurrent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

public class TaskQueue implements Executor {

    private final Logger logger;
    private final Executor executor;

    private final ConcurrentLinkedDeque<Runnable> queue = new ConcurrentLinkedDeque<>();
    private final AtomicBoolean isIdle = new AtomicBoolean(true);

    public TaskQueue(Executor executor) {
        this(executor, LoggerFactory.getLogger(TaskQueue.class));
    }

    public TaskQueue(Executor executor, Logger logger) {
        this.executor = executor;
        this.logger = logger;
    }

    private synchronized void taskFinished() {
        final Runnable nextTask = queue.poll();
        if (nextTask != null) {
            try {
                executor.execute(nextTask);
            } catch (Throwable t) {
                logger.error("Caught unexpected Throwable", t);
            } finally {
                taskFinished();
            }
        } else {
            // the last task in queue is finished
            isIdle.compareAndSet(false, true);
        }
    }

    @Override
    public synchronized void execute(final Runnable command) {
        if (command == null) {
            throw new NullPointerException("adding null task to task queue!");
        }

        final Runnable customTask = new Runnable() {
            @Override
            public void run() {
                try {
                    command.run();
                } catch (Throwable ignored) {
                    logger.error("Caught unexpected Throwable", ignored);
                }
                taskFinished();
            }
        };

        queue.add(customTask);
        if (isIdle.compareAndSet(true, false)) {
            executor.execute(queue.poll());
        }
    }
}
