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
//  Copyright (C) 2009, 2010, 2011, 2012, 2015
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
//
//   090720 Created for Mouse 1.1.
//  Version 1.2
//   100320 Bug fix in accept(): upgrade error info on success.
//   100320 Bug fix in rejectNot(): backtrack before registering failure.
//  Version 1.3
//   100429 Bug fix in errMerge(Phrase): assignment to errText replaced
//          by clear + addAll (assignment produced alias resulting in
//          explosion of errText in memo version).
//   101105 Changed errMerge(msg,pos) to errAdd(who).
//   101105 Commented error handling.
//   101129 Added 'boolReject'.
//   101203 Convert result of 'listErr' to printable.
//  Version 1.4
//   110918 Changed 'listErr' to separate 'not' texts as 'not expected'.
//   111004 Added methods to implement ^[s].
//   111004 Implemented method 'where' of Phrase.
//  Version 1.5
//   111027 Revised methods for ^[s] and ^[c].
//   111104 Implemented methods 'rule' and 'isTerm' of Phrase.
//  Version 1.5.1
//   120102 (Steve Owens) Ensure failure() method does not emit blank
//          line when error info is absent.
//  Version 1.6
//   120130 rhsText: return empty string for empty range.
//  Version 1.7
//   150629 Removed inner class Phrase that became a class on its own.
//          The new class Phrase has an additional parameter ('source')
//          to the constructor that has been added to its calls.
//          Used new Phrase methods in all 'accept' and 'reject'
//          services. Coded these services in a systematic way, which
//          made it possible to unify the services for predicates
//          into 'acceptPred' and 'rejectPred'. Service 'boolReject'
//          could be removed.
//   150725 Replaced method 'failure' by 'closeParser', called on both
//          successful and unsuccessful termination.
//          Added code in 'accept' and 'acceptInner' to propagate
//          deferred actions.
//
//=========================================================================

package com.hierynomus.msdtyp.sddl;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
//
//  ParserBase
//
//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

@SuppressWarnings("PMD")
class ParserBase implements com.hierynomus.msdtyp.sddl.CurrentRule {
    //-------------------------------------------------------------------
    //  Input
    //-------------------------------------------------------------------
    Source source;                    // Source of text to parse
    int endpos;                       // Position after the end of text
    int pos;                          // Current position in the text

    //-------------------------------------------------------------------
    //  Semantics (base)
    //-------------------------------------------------------------------
    protected com.hierynomus.msdtyp.sddl.SemanticsBase sem;

    //-------------------------------------------------------------------
    //  Trace string.
    //-------------------------------------------------------------------
    protected String trace = "";

    //-------------------------------------------------------------------
    //  Current phrase (top of parse stack).
    //-------------------------------------------------------------------
    Phrase current = null;

    //-------------------------------------------------------------------
    //  Constructor
    //-------------------------------------------------------------------
    protected ParserBase() {
    }

    //-------------------------------------------------------------------
    //  Initialize parsing
    //-------------------------------------------------------------------
    public void init(Source src) {
        source = src;
        pos = 0;
        endpos = source.end();
        current = new Phrase("", "", 0, source); // Dummy bottom of parse stack
    }

    //-------------------------------------------------------------------
    //  Implementation of Parser interface CurrentRule
    //-------------------------------------------------------------------
    public Phrase lhs() {
        return current;
    }

    public Phrase rhs(int i) {
        return current.rhs.elementAt(i);
    }

    public int rhsSize() {
        return current.rhs.size();
    }

    public String rhsText(int i, int j) {
        if (j <= i) return "";
        return source.at(rhs(i).start, rhs(j - 1).end);
    }

    //-------------------------------------------------------------------
    //  Set trace
    //-------------------------------------------------------------------
    public void setTrace(String trace) {
        this.trace = trace;
        sem.trace = trace;
    }

    //-------------------------------------------------------------------
    //  Close parser: print messages (if not caught otherwise).
    //-------------------------------------------------------------------
    protected void closeParser(boolean ok) {
        current.actExec();
        if (!ok && current.hwm >= 0)
            System.out.println(current.errMsg());
    }

    //=====================================================================
    //
    //  Methods called from parsing procedures
    //
    //=====================================================================
    //-------------------------------------------------------------------
    //  Initialize processing of a nonterminal:
    //  create new Phrase and push it on compile stack.
    //-------------------------------------------------------------------
    protected void begin(final String name) {
        Phrase p = new Phrase(name, name, pos, source);
        p.parent = current;
        current = p;
    }

    protected void begin(final String name, final String diag) {
        Phrase p = new Phrase(name, diag, pos, source);
        p.parent = current;
        current = p;
    }

    //-------------------------------------------------------------------
    //  Accept Rule
    //-------------------------------------------------------------------
    protected boolean accept() {
        Phrase p = pop();                // Pop the finishing Phrase
        // Finalize p:
        p.success = true;                //   Indicate p successful
        p.rhs = null;                    //   Discard rhs of p
        // Update parent Phrase:
        current.end = pos;               //   End of text
        current.rhs.add(p);              //   Add p to the rhs
        current.hwmUpdFrom(p);           //   Update failure history
        current.defAct.addAll(p.defAct); //   Propagate deferred actions
        return true;
    }

    //-------------------------------------------------------------------
    //  Accept Inner
    //-------------------------------------------------------------------
    protected boolean acceptInner() {
        Phrase p = pop();                // Pop the finishing Phrase
        // Finalize p:
        p.success = true;                //   Indicate p successful
        // Update parent Phrase:
        current.end = pos;               //   End of text
        current.rhs.addAll(p.rhs);       //   Append p's rhs to the rhs
        current.hwmUpdFrom(p);           //   Update failure history
        current.defAct.addAll(p.defAct); //   Propagate deferred actions
        return true;
    }

    //-------------------------------------------------------------------
    //  Accept predicate
    //-------------------------------------------------------------------
    protected boolean acceptPred() {
        Phrase p = pop();                // Pop the finishing Phrase
        pos = p.start;                   // Do not consume input
        // Finalize p:
        p.end = pos;                     //   Reset end of text
        p.success = true;                //   Indicate p successful
        p.rhs = null;                    //   Discard rhs of p
        p.hwmClear();                    //   Remove failure history
        // Update parent Phrase:
        current.end = pos;               //   End of text
        return true;
    }

    //-------------------------------------------------------------------
    //  Reject Rule
    //-------------------------------------------------------------------
    protected boolean reject() {
        Phrase p = pop();                // Pop the finishing Phrase
        pos = p.start;                   // Do not consume input
        // Finalize p:
        p.end = pos;                     //   Reset end of text
        p.success = false;               //   Indicate p failed
        p.rhs = null;                    //   Discard rhs of p
        if (p.hwm <= pos)                  //   If hwm reached or passed..
            p.hwmSet(p.diag, p.start);      //   ..register failure of p
        // Update parent Phrase:
        current.end = pos;               //   End of text
        current.hwmUpdFrom(p);           //   Update failure history
        return false;
    }

    //-------------------------------------------------------------------
    //  Reject Inner
    //-------------------------------------------------------------------
    protected boolean rejectInner() {
        Phrase p = pop();                // Pop the finishing Phrase
        pos = p.start;                   // Do not consume input
        // Finalize p:
        p.end = pos;                     //   Reset end of text
        p.success = false;               //   Indicate p failed
        p.rhs = null;                    //   Discard rhs of p
        // Update parent Phrase:
        current.end = pos;               //   End of text
        current.hwmUpdFrom(p);           //   Update failure history
        return false;
    }

    //-------------------------------------------------------------------
    //  Reject predicate
    //-------------------------------------------------------------------
    protected boolean rejectPred() {
        Phrase p = pop();                // Pop the finishing Phrase
        pos = p.start;                   // Do not consume input
        // Finalize p:
        p.end = pos;                     //   Reset end of text
        p.success = false;               //   Indicate p failed
        p.rhs = null;                    //   Discard rhs of p
        p.hwmSet(p.diag, pos);            //   Register 'xxx (not) expected'
        // Update parent Phrase:
        current.end = pos;               //   End of text
        current.hwmUpdFrom(p);           //   Update failure history
        return false;
    }


    //-------------------------------------------------------------------
    //  Execute expression 'c'
    //-------------------------------------------------------------------
    protected boolean next(char ch) {
        if (pos < endpos && source.at(pos) == ch) return consume(1);
        else return fail("'" + ch + "'");
    }

    //-------------------------------------------------------------------
    //  Execute expression ^'c'
    //-------------------------------------------------------------------
    protected boolean nextNot(char ch) {
        if (pos < endpos && source.at(pos) != ch) return consume(1);
        else return fail("not '" + ch + "'");
    }

    //-------------------------------------------------------------------
    //  Execute expression &'c', !^'c'
    //-------------------------------------------------------------------
    protected boolean ahead(char ch) {
        if (pos < endpos && source.at(pos) == ch) return true;
        else return fail("'" + ch + "'");
    }

    protected boolean aheadNotNot(char ch)  // temporary
    {
        return ahead(ch);
    }

    //-------------------------------------------------------------------
    //  Execute expression !'c', &^'c'
    //-------------------------------------------------------------------
    protected boolean aheadNot(char ch) {
        if (pos < endpos && source.at(pos) == ch) return fail("not '" + ch + "'");
        else return true;
    }


    //-------------------------------------------------------------------
    //  Execute expression "s"
    //-------------------------------------------------------------------
    protected boolean next(String s) {
        int lg = s.length();
        if (pos + lg <= endpos && source.at(pos, pos + lg).equals(s)) return consume(lg);
        else return fail("'" + s + "'");
    }

    //-------------------------------------------------------------------
    //  Execute expression &"s"
    //-------------------------------------------------------------------
    protected boolean ahead(String s) {
        int lg = s.length();
        if (pos + lg <= endpos && source.at(pos, pos + lg).equals(s)) return true;
        else return fail("'" + s + "'");
    }

    //-------------------------------------------------------------------
    //  Execute expression !"s"
    //-------------------------------------------------------------------
    protected boolean aheadNot(String s) {
        int lg = s.length();
        if (pos + lg <= endpos && source.at(pos, pos + lg).equals(s)) return fail("not '" + s + "'");
        else return true;
    }


    //-------------------------------------------------------------------
    //  Execute expression [s]
    //-------------------------------------------------------------------
    protected boolean nextIn(String s) {
        if (pos < endpos && s.indexOf(source.at(pos)) >= 0) return consume(1);
        else return fail("[" + s + "]");
    }

    //-------------------------------------------------------------------
    //  Execute expression ^[s]
    //-------------------------------------------------------------------
    protected boolean nextNotIn(String s) {
        if (pos < endpos && s.indexOf(source.at(pos)) < 0) return consume(1);
        else return fail("not [" + s + "]");
    }

    //-------------------------------------------------------------------
    //  Execute expression &[s], !^[s]
    //-------------------------------------------------------------------
    protected boolean aheadIn(String s) {
        if (pos < endpos && s.indexOf(source.at(pos)) >= 0) return true;
        else return fail("[" + s + "]");
    }

    protected boolean aheadNotNotIn(String s) // temporary
    {
        return aheadIn(s);
    }

    //-------------------------------------------------------------------
    //  Execute expression ![s], &^[s]
    //-------------------------------------------------------------------
    protected boolean aheadNotIn(String s) {
        if (pos < endpos && s.indexOf(source.at(pos)) >= 0) return fail("not [" + s + "]");
        else return true;
    }


    //-------------------------------------------------------------------
    //  Execute expression [a-z]
    //-------------------------------------------------------------------
    protected boolean nextIn(char a, char z) {
        if (pos < endpos && source.at(pos) >= a && source.at(pos) <= z)
            return consume(1);
        else return fail("[" + a + "-" + z + "]");
    }

    //-------------------------------------------------------------------
    //  Execute expression &[a-z]
    //-------------------------------------------------------------------
    protected boolean aheadIn(char a, char z) {
        if (pos < endpos && source.at(pos) >= a && source.at(pos) <= z)
            return true;
        else return fail("[" + a + "-" + z + "]");
    }

    //-------------------------------------------------------------------
    //  Execute expression ![a-z]
    //-------------------------------------------------------------------
    protected boolean aheadNotIn(char a, char z) {
        if (pos < endpos && source.at(pos) >= a && source.at(pos) <= z)
            return fail("not [" + a + "-" + z + "]");
        else return true;
    }


    //-------------------------------------------------------------------
    //  Execute expression _
    //-------------------------------------------------------------------
    protected boolean next() {
        if (pos < endpos) return consume(1);
        else return fail("any character");
    }

    //-------------------------------------------------------------------
    //  Execute expression &_
    //-------------------------------------------------------------------
    protected boolean ahead() {
        if (pos < endpos) return true;
        else return fail("any character");
    }

    //-------------------------------------------------------------------
    //  Execute expression !_
    //-------------------------------------------------------------------
    protected boolean aheadNot() {
        if (pos < endpos) return fail("end of text");
        else return true;
    }


    //-------------------------------------------------------------------
    //  Pop Phrase from compile stack
    //-------------------------------------------------------------------
    private Phrase pop() {
        Phrase p = current;
        current = p.parent;
        p.parent = null;
        return p;
    }

    //-------------------------------------------------------------------
    //  Consume terminal
    //-------------------------------------------------------------------
    private boolean consume(int n) {
        Phrase p = new Phrase("", "", pos, source);
        pos += n;
        p.end = pos;
        current.rhs.add(p);
        current.end = pos;
        return true;
    }

    //-------------------------------------------------------------------
    //  Fail
    //-------------------------------------------------------------------
    private boolean fail(String msg) {
        current.hwmUpd(msg, pos);
        return false;
    }
}



