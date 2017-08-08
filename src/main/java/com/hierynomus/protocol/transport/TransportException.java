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
package com.hierynomus.protocol.transport;

import com.hierynomus.protocol.commons.concurrent.ExceptionWrapper;

import java.io.IOException;

public class TransportException extends IOException {
    public static final ExceptionWrapper<TransportException> Wrapper = new ExceptionWrapper<TransportException>() {
        @Override
        public TransportException wrap(Throwable throwable) {
            if (throwable instanceof TransportException) {
                return (TransportException) throwable;
            }
            return new TransportException(throwable);
        }
    };

    public TransportException(Throwable ioe) {
        super(ioe);
    }

    public TransportException(String s) {
        super(s);
    }
}
