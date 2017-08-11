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
package com.hierynomus.msdfsc

import java.util.concurrent.ExecutionException
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

class DirectFuture<V> implements Future<V> {

  private V contents

  DirectFuture(V contents) {
    this.contents = contents
  }

  @Override
  boolean cancel(boolean mayInterruptIfRunning) {
    return false
  }

  @Override
  boolean isCancelled() {
    return false
  }

  @Override
  boolean isDone() {
    return true
  }

  @Override
  V get() throws InterruptedException, ExecutionException {
    return contents
  }

  @Override
  V get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
    return contents
  }
}
