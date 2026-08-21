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
package com.hierynomus.smbfs;

import com.hierynomus.smbj.share.DiskShare;

import java.io.Closeable;
import java.io.IOException;

/**
 * Provides access to a (reused) {@link DiskShare}. Unlike a plain connection-per-call
 * approach, an implementation is expected to keep the underlying connection/session/share
 * alive across calls to {@link #getShare(String)} and only reconnect when needed.
 */
interface ShareSource extends Closeable {

    DiskShare getShare(String name) throws IOException;
}
