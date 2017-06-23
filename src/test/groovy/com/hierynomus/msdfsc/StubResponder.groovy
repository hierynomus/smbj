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

import com.hierynomus.mssmb2.SMB2Packet

class StubResponder {

  Map<Class, Queue<SMB2Packet>> responses = [:]

  def register(Class c, SMB2Packet response) {
    def queue = responses.get(c)
    if (!queue) {
      queue = new ArrayDeque<SMB2Packet>()
      responses.put(c, queue)
    }
    queue.add(response)
  }

  SMB2Packet respond(Object o) {
    def clazz = o.getClass()
    if (responses.containsKey(clazz)) {
      return responses.get(clazz).poll()
    }
    throw new IllegalArgumentException("$clazz has no registered response")
  }
}
