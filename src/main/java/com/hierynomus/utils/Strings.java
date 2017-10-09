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
package com.hierynomus.utils;

import java.util.ArrayList;
import java.util.List;

public class Strings {

    /**
     * Split a string on a character.
     *
     * @param string The string to split.
     * @param c The character to split on.
     * @return The splitted parts of the string.
     */
    public static List<String> split(String string, char c) {
        List<String> parts = new ArrayList<>();
        int off = 0;
        int next;
        while ((next = string.indexOf(c, off)) != -1) {
            parts.add(string.substring(off, next));
            off = next + 1;
        }
        parts.add(string.substring(off));
        return parts;
    }

    /**
     * Join a string on a character.
     *
     * @param strings The strings to join.
     * @param c The character to join on.
     * @return The joined parts of the string.
     */
    public static String join(List<String> strings, char c) {
        StringBuilder joiner = new StringBuilder();
        for (int i = 0; i < strings.size(); i++) {
            if (i > 0) {
                joiner.append(c);
            }
            joiner.append(strings.get(i));
        }
        return joiner.toString();
    }

}
