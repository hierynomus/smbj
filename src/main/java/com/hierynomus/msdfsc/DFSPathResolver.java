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
package com.hierynomus.msdfsc;

import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.PathResolveException;
import com.hierynomus.smbj.share.PathResolver;

public class DFSPathResolver implements PathResolver {
    private DFS dfs = new DFS();
    @Override
    public SmbPath resolve(Session session, SmbPath smbPath) throws PathResolveException {
        try {
            return dfs.resolveDFS(session, smbPath);
        } catch (DFSException e) {
            throw new PathResolveException(e);
        }
    }
}
