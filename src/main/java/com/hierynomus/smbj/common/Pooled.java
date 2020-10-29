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
package com.hierynomus.smbj.common;

import java.util.concurrent.atomic.AtomicInteger;

public class Pooled<A extends Pooled<A>> {

    /**
     * A newly created {@link Pooled} object has 1 lease outstanding (the created object)
     */
    private final AtomicInteger leases = new AtomicInteger(1);

    /**
     * Takes a lease on the pooled object.
     * @return <code>this</code> if the object is still valid (has at least 1 lease), else <code>null</code>
     */
    public A lease() {
        if (leases.getAndIncrement() > 0) {
            return (A) this;
        }
        return null;
    }

    /**
     * Releases the pooled object.
     * If this was the last outstanding lease, {@link #release()} returns <code>true</code>.
     * @return <code>true</code> if this was the last outstanding lease. Else <code>false</code>
     */
    public boolean release() {
        return leases.decrementAndGet() <= 0;
    }
}

