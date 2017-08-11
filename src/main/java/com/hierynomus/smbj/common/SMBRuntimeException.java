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

import com.hierynomus.protocol.commons.concurrent.ExceptionWrapper;

public class SMBRuntimeException extends RuntimeException {
    public static final ExceptionWrapper<SMBRuntimeException> Wrapper = new ExceptionWrapper<SMBRuntimeException>() {
        @Override
        public SMBRuntimeException wrap(Throwable throwable) {
            if (throwable instanceof SMBRuntimeException) {
                return (SMBRuntimeException) throwable;
            } else {
                return new SMBRuntimeException(throwable);
            }
        }
    };

    public SMBRuntimeException(Throwable t) {
        super(t);
    }

    public SMBRuntimeException(String msg) {
        super(msg);
    }

    public SMBRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }
}
