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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

import java.util.Arrays;

public class ReferralCacheNodeTest {
    @Test
    public void shouldBuildTrieWithEntryAtLeaf() {
        ReferralCache.ReferralCacheNode root = new ReferralCache.ReferralCacheNode("<root>");
        ReferralCache.ReferralCacheEntry entry = mock(ReferralCache.ReferralCacheEntry.class);

        root.addReferralEntry(Arrays.asList("path", "to", "entry").iterator(), entry);

        assertTrue(root.getChildNodes().containsKey("path"));
        assertEquals(1, root.getChildNodes().size());
        ReferralCache.ReferralCacheNode pathNode = root.getChildNodes().get("path");
        assertEquals("path", pathNode.getPathComponent());
        assertTrue(pathNode.getChildNodes().containsKey("to"));
        assertEquals(1, pathNode.getChildNodes().size());

        assertSame(entry, root.getReferralEntry(Arrays.asList("path", "to", "entry").iterator()));
    }

    @Test
    public void shouldReturnNullForNonMatchingPrefix() {
        ReferralCache.ReferralCacheNode root = new ReferralCache.ReferralCacheNode("<root>");
        ReferralCache.ReferralCacheEntry entry = mock(ReferralCache.ReferralCacheEntry.class);

        root.addReferralEntry(Arrays.asList("path", "to", "entry").iterator(), entry);

        assertNull(root.getReferralEntry(Arrays.asList("path", "wrong", "left", "turn").iterator()));
    }

    @Test
    public void shouldReturnDeepestMatch() {
        ReferralCache.ReferralCacheNode root = new ReferralCache.ReferralCacheNode("<root>");
        ReferralCache.ReferralCacheEntry entry = mock(ReferralCache.ReferralCacheEntry.class);
        ReferralCache.ReferralCacheEntry entry2 = mock(ReferralCache.ReferralCacheEntry.class);

        root.addReferralEntry(Arrays.asList("left", "right").iterator(), entry);
        root.addReferralEntry(Arrays.asList("left", "right", "left").iterator(), entry2);

        assertSame(entry, root.getReferralEntry(Arrays.asList("left", "right").iterator()));
        assertSame(entry2, root.getReferralEntry(Arrays.asList("left", "right", "left").iterator()));
    }

    @Test
    public void shouldIgnorePathCase() {
        ReferralCache.ReferralCacheNode root = new ReferralCache.ReferralCacheNode("<root>");
        ReferralCache.ReferralCacheEntry entry = mock(ReferralCache.ReferralCacheEntry.class);

        root.addReferralEntry(Arrays.asList("path", "to", "entry").iterator(), entry);

        assertSame(entry, root.getReferralEntry(Arrays.asList("PATH", "TO", "ENTRY").iterator()));
    }
}
