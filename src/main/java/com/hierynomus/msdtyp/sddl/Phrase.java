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
//=========================================================================
//
//  Part of PEG parser generator Mouse.
//
//  Copyright (C) 2009, 2011, 2015
//  by Roman R. Redziejowski (www.romanredz.se).
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
//-------------------------------------------------------------------------
//
//  Change log
//   Version 1.7
//    150629 Extracted from Parser Base and made into a separate class,
//           replacing the interface 'Phrase'.
//           This required an additional variable 'source' and constructor
//           parameter to set it.
//           Error history is renamed to 'high-water mark', with methods
//           'hwmClear', 'hwmSet', 'hwmUpd' and 'hwmUpdFrom' accessible
//           only from package 'runtime'.
//           All methods previously accessible via interface 'Phrase'
//           are preserved and public, plus new method 'errAdd'.
//    150724 Added 'defAct' to keep deferred actions, and methods
//           'actAdd', 'actClear', and 'actExec' for handling them.
//
//=========================================================================

package com.hierynomus.msdtyp.sddl;

import java.util.Vector;


//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
//
//  Phrase
//
//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

@SuppressWarnings("PMD")
class Phrase {
    //===================================================================
    //
    //  Data
    //
    //===================================================================

    final String name;
    final String diag;
    final int start;
    int end;
    boolean success;
    Vector<Phrase> rhs = new Vector<Phrase>(10, 10);
    Object value = null;
    Phrase parent = null;
    Source source;

    //-----------------------------------------------------------------
    //  Information about the failure farthest down in the text
    //  encountered while processing this Phrase.
    //  It can only be failure of a rule, predicate, or terminal.
    //  - 'hwm' (high water mark) is the position of the failure,
    //     or -1 if there was none.
    //  - 'hwmExp' identifies the expression(s) that failed at 'hwm'.
    //     There may be several such expressions if 'hwm' was reached
    //     on several attempts. The expressions are identified
    //     by their diagnostic names.
    //-----------------------------------------------------------------
    int hwm = -1;
    Vector<String> hwmExp = new Vector<String>();

    //-----------------------------------------------------------------
    //  Deferred actions
    //-----------------------------------------------------------------
    Vector<Deferred> defAct = new Vector<Deferred>();


    //===================================================================
    //
    //  Constructor
    //
    //===================================================================

    protected Phrase(final String name, final String diag, int start, final Source source) {
        this.name = name;
        this.diag = diag;
        this.start = start;
        this.end = start;
        this.source = source;
    }

    //===================================================================
    //
    //  Methods called from semantic procedures
    //
    //===================================================================
    //-----------------------------------------------------------------
    //  Set value
    //-----------------------------------------------------------------
    public void put(Object o) {
        value = o;
    }

    //-----------------------------------------------------------------
    //  Get value
    //-----------------------------------------------------------------
    public Object get() {
        return value;
    }

    //-----------------------------------------------------------------
    //  Get text
    //-----------------------------------------------------------------
    public String text() {
        return source.at(start, end);
    }

    //-------------------------------------------------------------------
    //  Get i-th character of text
    //-------------------------------------------------------------------
    public char charAt(int i) {
        return source.at(start + i);
    }

    //-----------------------------------------------------------------
    //  Is text empty?
    //-----------------------------------------------------------------
    public boolean isEmpty() {
        return start == end;
    }

    //-------------------------------------------------------------------
    //  Get name of rule that created this Phrase.
    //-------------------------------------------------------------------
    public String rule() {
        return name;
    }

    //-------------------------------------------------------------------
    //  Was this Phrase created by rule 'rule'?
    //-------------------------------------------------------------------
    public boolean isA(String rule) {
        return name.equals(rule);
    }

    //-------------------------------------------------------------------
    //  Was this Phrase created by a terminal?
    //-------------------------------------------------------------------
    public boolean isTerm() {
        return name.isEmpty();
    }

    //-----------------------------------------------------------------
    //  Describe position of i-th character of the Phrase in source text.
    //-----------------------------------------------------------------
    public String where(int i) {
        return source.where(start + i);
    }

    //-----------------------------------------------------------------
    //  Get error message
    //-----------------------------------------------------------------
    public String errMsg() {
        if (hwm < 0) return "";
        return source.where(hwm) + ":" + listErr();
    }

    //-----------------------------------------------------------------
    //  Clear error information
    //-----------------------------------------------------------------
    public void errClear() {
        hwmClear();
    }

    //-----------------------------------------------------------------
    //  Add information about 'expr' failing at the i-th character
    //  of this Phrase.
    //-----------------------------------------------------------------
    public void errAdd(final String expr, int i) {
        hwmSet(expr, start + i);
    }

    //-----------------------------------------------------------------
    //  Clear deferred actions
    //-----------------------------------------------------------------
    public void actClear() {
        defAct.clear();
    }

    //-----------------------------------------------------------------
    //  Add deferred action
    //-----------------------------------------------------------------
    public void actAdd(Deferred a) {
        defAct.add(a);
    }

    //-----------------------------------------------------------------
    //  Execute deferred actions
    //-----------------------------------------------------------------
    public void actExec() {
        for (Deferred a : defAct) a.exec();
        defAct.clear();
    }


    //===================================================================
    //
    //  Metods called from Parser
    //
    //===================================================================
    //-----------------------------------------------------------------
    //  Clear high-water mark
    //-----------------------------------------------------------------
    void hwmClear() {
        hwmExp.clear();
        hwm = -1;
    }

    //-----------------------------------------------------------------
    //  Set fresh mark ('what' failed 'where'), discarding any previous.
    //-----------------------------------------------------------------
    void hwmSet(final String what, int where) {
        hwmExp.clear();
        hwmExp.add(what);
        hwm = where;
    }

    //-----------------------------------------------------------------
    //  Add info about 'what' failing at position 'where'.
    //-----------------------------------------------------------------
    void hwmUpd(final String what, int where) {
        if (hwm > where) return;   // If 'where' older: forget
        if (hwm < where)           // If 'where' newer: replace
        {
            hwmExp.clear();
            hwm = where;
        }
        // If same position: add
        hwmExp.add(what);
    }

    //-----------------------------------------------------------------
    //  Update error high-water mark with that from Phrase 'p'.
    //-----------------------------------------------------------------
    void hwmUpdFrom(final Phrase p) {
        if (hwm > p.hwm) return;// If p's info older: forget
        if (hwm < p.hwm)        // If p's info  newer: replace
        {
            hwmExp.clear();
            hwm = p.hwm;
        }
        hwmExp.addAll(p.hwmExp);    // If same position: add
    }


    //===================================================================
    //
    //  Private methods
    //
    //===================================================================
    //-----------------------------------------------------------------
    //  Translate high-water mark into error message.
    //-----------------------------------------------------------------
    private String listErr() {
        StringBuilder one = new StringBuilder();
        StringBuilder two = new StringBuilder();
        Vector<String> done = new Vector<String>();
        for (String s : hwmExp) {
            if (done.contains(s)) continue;
            done.add(s);
            if (s.startsWith("not "))
                toPrint(" or " + s.substring(4), two);
            else
                toPrint(" or " + s, one);
        }

        if (one.length() > 0) {
            if (two.length() == 0)
                return " expected " + one.toString().substring(4);
            else
                return " expected " + one.toString().substring(4) +
                    "; not expected " + two.toString().substring(4);
        } else
            return " not expected " + two.toString().substring(4);
    }

    //-----------------------------------------------------------------
    //  Convert string to printable and append to StringBuilder.
    //-----------------------------------------------------------------
    private void toPrint(final String s, StringBuilder sb) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\b':
                    sb.append("\\b");
                    continue;
                case '\f':
                    sb.append("\\f");
                    continue;
                case '\n':
                    sb.append("\\n");
                    continue;
                case '\r':
                    sb.append("\\r");
                    continue;
                case '\t':
                    sb.append("\\t");
                    continue;
                default:
                    if (c < 32 || c > 256) {
                        String u = "000" + Integer.toHexString(c);
                        sb.append("\\u" + u.substring(u.length() - 4, u.length()));
                    } else sb.append(c);
                    continue;
            }
        }
    }
}
