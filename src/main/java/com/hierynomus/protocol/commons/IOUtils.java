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
package com.hierynomus.protocol.commons;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IOUtils {

    private static final Logger LOG = LoggerFactory.getLogger(IOUtils.class);

    public static void closeQuietly(AutoCloseable... closeables) {
        for (AutoCloseable c : closeables) {
            try {
                if (c != null) {
                    c.close();
                }
            } catch (Exception logged) {
                LOG.warn("Error closing {} - {}", c, logged);
            }
        }
    }

    public static void closeSilently(AutoCloseable... closeables) {
        for (AutoCloseable c : closeables) {
            try {
                if (c != null) {
                    c.close();
                }
            } catch (Exception ignored) {
                // Dismiss the exception
            }
        }
    }
}
