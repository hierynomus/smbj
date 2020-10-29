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
package com.hierynomus.smbj.paths;

import com.hierynomus.mserref.NtStatus;

public class PathResolveException extends Exception {
    private final long status;

    public PathResolveException(long status) {
        this.status = status;
    }

    public PathResolveException(long status, String message) {
        super(message);
        this.status = status;
    }

    public PathResolveException(Throwable cause) {
        super(cause);
        this.status = NtStatus.STATUS_OTHER.getValue();
    }

    public long getStatusCode() {
        return status;
    }

    public NtStatus getStatus() {
        return NtStatus.valueOf(status);
    }
}
