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

import com.hierynomus.protocol.commons.exception.ExceptionWrapper;

import java.io.IOException;

public class SMBIOException extends IOException {
    public static ExceptionWrapper<SMBIOException> Wrapper = new ExceptionWrapper<SMBIOException>() {
        @Override
        public SMBIOException wrap(Throwable throwable) {
            if (throwable instanceof SMBIOException) {
                return (SMBIOException) throwable;
            } else {
                return new SMBIOException(throwable);
            }
        }
    };

    public SMBIOException(String message) {
        super(message);
    }

    public SMBIOException(Throwable t) {
        super(t);
    }
}
