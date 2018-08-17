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
package com.hierynomus.smbj;

public final class GSSContextConfig {

    private boolean requestMutualAuth;
    private boolean requestCredDeleg;
    // TODO: Implement other option
//    private boolean requestReplayDet;
//    private boolean requestSequenceDet;
//    private boolean requestAnonymity;
//    private boolean requestConf;
//    private boolean requestInteg;
//    private int requestLifetime;

    public static GSSContextConfig createDefaultConfig() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder()
            .withRequestMutualAuth(true)
            .withRequestCredDeleg(false);
    }

    private GSSContextConfig() {
    }

    private GSSContextConfig(GSSContextConfig other) {
        this();
        requestMutualAuth = other.requestMutualAuth;
        requestCredDeleg = other.requestCredDeleg;
    }

    public boolean isRequestMutualAuth() {
        return requestMutualAuth;
    }

    public boolean isRequestCredDeleg() {
        return requestCredDeleg;
    }

    public static class Builder {
        private GSSContextConfig config;

        Builder() {
            config = new GSSContextConfig();
        }

        public Builder withRequestMutualAuth(boolean requestMutualAuth) {
            config.requestMutualAuth = requestMutualAuth;
            return this;
        }

        public Builder withRequestCredDeleg(boolean requestCredDeleg) {
            config.requestCredDeleg = requestCredDeleg;
            return this;
        }

        public GSSContextConfig build() {
            return new GSSContextConfig(config);
        }
    }

}
