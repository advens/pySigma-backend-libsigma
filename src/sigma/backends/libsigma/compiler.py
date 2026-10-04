# SPDX-License-Identifier: LGPL-2.1-only
"""pySigma front-end: compile Sigma rules to a libsigma ``.sigmac`` artifact.

Sigma is the authoring language. This maps a parsed rule's boolean detection
tree (pySigma expands selections and quantifiers such as ``1 of`` and ``all of``
into an AND/OR/NOT tree of leaf field-expressions) onto the compiled model:

  * each leaf field-expression           -> a single-predicate selection
  * the AND/OR/NOT tree                   -> the rule's condition RPN
  * Sigma value modifiers / value types   -> predicate ops:
        plain / wildcards   -> EQ / CONTAINS / STARTSWITH / ENDSWITH / RE
        |re                 -> RE, or EQ/CONTAINS/STARTSWITH/ENDSWITH when the
                               pattern is exactly a string predicate
        |cidr               -> CIDR (v4/v6)
        |gt|gte|lt|lte      -> numeric   field:null -> EXISTS (negated)
        |exists             -> EXISTS
        |windash / |base64offset -> OR of the expanded SigmaString leaves
          (pySigma yields SigmaExpansion; we lower, we do not add opcodes)

The matcher never parses YAML. Correlation rules are not emitted into the
selection-match artifact. They are serialized to the sibling
``rules.corr.json`` (:mod:`sigma.backends.libsigma.correlation`), which
libsigma's correlator loads.

Display metadata (uuid, title, level, mitre, verdict) rides a JSON sidecar keyed
by rule_id, the binary carries only what the matcher needs.
"""

from __future__ import annotations

import re as _re
from dataclasses import dataclass, field as _dc_field

# ADR-0072 P2.5, sound literal ANCHOR extraction from regex (|re) predicates.
# `sre_parse` (CPython's regex parser) gives the regex AST; we walk it to find a
# literal substring that EVERY string matching the regex MUST contain.  The module
# moved to `re._parser` in 3.11+; keep the legacy import as a fallback so the
# compiler runs on older interpreters too.
try:  # CPython 3.11+
    import re._parser as _sre_parse  # type: ignore[attr-defined]
    import re._constants as _sre_constants  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - <3.11
    import sre_parse as _sre_parse  # type: ignore[no-redef]
    import sre_constants as _sre_constants  # type: ignore[no-redef]

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.conditions import (
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
    ConditionValueExpression,
)
from types import SimpleNamespace

from sigma.types import (
    SigmaString,
    SigmaNumber,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaRegularExpression,
    SigmaNull,
    SigmaExists,
)

# |cased and |fieldref support. Guarded so an older pySigma without either type
# does not break the whole compiler; the feature simply no-ops (isinstance
# against () is always False): a cased string falls back to case-insensitive, and
# a field reference falls through to the "unsupported value type" error (reported,
# rule skipped) exactly as before.
try:
    from sigma.types import SigmaCasedString
except ImportError:  # pragma: no cover
    SigmaCasedString = ()
try:
    from sigma.types import SigmaFieldReference
except ImportError:  # pragma: no cover
    SigmaFieldReference = ()
# |windash / |base64offset arrive as SigmaExpansion (OR-linked variant list).
# Expanding is a backend job; without this import the leaf falls through to
# "unsupported value type" and the rule is dropped. Guarded like the types above.
try:
    from sigma.types import SigmaExpansion
except ImportError:  # pragma: no cover
    SigmaExpansion = ()
try:
    from sigma.types import Placeholder
except ImportError:  # pragma: no cover
    Placeholder = ()

from .format import (SigmaDbBuilder, Op, Verdict, CTok, NO_VALUE, PF_CASE, PF_NEGATE,
                     PF_FIELDREF, ANY_FIELD, MAX_CLAUSES)

# ADR-0072 P2, SIMD literal prefilter.  A "required literal" is a literal
# operand of a NON-NEGATED EQ/CONTAINS/STARTSWITH/ENDSWITH predicate that sits in
# a MUST-MATCH (AND) position of the rule's condition: if its bytes are absent
# from the event's searchable text the rule provably cannot match, so the rule is
# not a prefilter candidate.  Length is UTF-8 bytes, not Python codepoints: a
# single emoji is 4 bytes and is a sound, selective needle on ASCII command
# lines (SigmaHQ "emoji in CommandLine" rules are ~1000 contains each). ASCII
# 1-2 byte tokens (`rm`, `M`) stay out (present in almost every line). 2-byte
# non-ASCII letters (Cyrillic homoglyphs) are posted: they do not occur in
# ASCII haystacks. Empty/whitespace still carries no signal -> always-verify.
# 2-byte ASCII that is ALL non-alnum (`^^`, `^|`) is posted: it does not
# appear in ordinary words, so it will not saturate Teddy. 2-byte punct+alnum
# (`-W`, `-f`) is posted: compiler flags are selective enough to gate a
# regex. Slash+alnum (`/w`) is posted: Teddy is per-field, and `/w` on Image
# is the Linux/macOS `w` binary (wget/who are extra candidates, then
# verify). Backslash+alnum (`\w`) stays out: it is a substring of almost
# every Windows Image (`\windows`). 2-byte all-alnum (`rm`, `ws`) stays out.
_PREFILTER_MIN_LEN = 3
_BACKSLASH = 0x5C


def _prefilter_needle_ok(s: str) -> bool:
    """True when *s* is distinctive enough to post as a Teddy needle."""
    raw = s.encode("utf-8")
    n = len(raw)
    if n >= _PREFILTER_MIN_LEN:
        return True
    if n < 2:
        return False
    if any(b >= 0x80 for b in raw):
        return True
    if any(b <= 0x20 for b in raw):
        return False
    if any(b == _BACKSLASH for b in raw):
        return False
    alnum = [
        0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A
        for b in raw
    ]
    if all(alnum):
        return False
    return True

# |windash is a 5^k cartesian over word-boundary dashes. Unbounded fan-out
# into selections / RPN / litidx needles would blow Teddy. A leaf over this
# cap raises CompileError; the rule is recorded in errors and not emitted
# (whole-rule, not a per-leaf skip, not a silent truncate). 128 covers the
# 5^3 = 125 three-dash case; four dashes (625) still error.
_EXPANSION_MAX = 128
# A `|re: 'foo|bar'` of literal alts is OR of string predicates, not one PCRE.
# Cap matches windash: past this the rule stays Op.RE (not a silent truncate).
_RE_ALT_MAX = 128
# Production compile skips these Sigma statuses (dead / withdrawn rules).
# experimental and test stay: that is most of SigmaHQ.
_STATUS_SKIP = frozenset({"deprecated", "unsupported"})
# |expand value lists are operator-controlled (unlike windash's 5^k cartesian)
# but still must not bake an unbounded OR into the artifact. Over this cap the
# rule is a CompileError, not a silent truncate (same discipline as windash).
_PLACEHOLDER_MAX = 256
_PREFILTER_STR_OPS = frozenset({Op.EQ, Op.CONTAINS, Op.STARTSWITH, Op.ENDSWITH})

# ADR-0072 P2.5, opcode identities (resolved once; names are stable across the
# 3.x line even though the holding module moved).  Any opcode NOT named here is,
# by construction, treated as a run-breaker that yields no anchor (conservative).
_OP_LITERAL = _sre_constants.LITERAL
_OP_BRANCH = _sre_constants.BRANCH
_OP_SUBPATTERN = _sre_constants.SUBPATTERN
_OP_MAX_REPEAT = _sre_constants.MAX_REPEAT
_OP_MIN_REPEAT = _sre_constants.MIN_REPEAT
_OP_IN = _sre_constants.IN
_OP_ANY = _sre_constants.ANY
_OP_AT = _sre_constants.AT
_AT_START = frozenset({
    _sre_constants.AT_BEGINNING,
    _sre_constants.AT_BEGINNING_STRING,
})
_AT_STOP = frozenset({
    _sre_constants.AT_END,
    _sre_constants.AT_END_STRING,
})
_SRE_IGNORECASE = _sre_constants.SRE_FLAG_IGNORECASE
_SRE_MULTILINE = _sre_constants.SRE_FLAG_MULTILINE
# ATOMIC_GROUP / POSSESSIVE_REPEAT exist on newer interpreters; tolerate absence.
_OP_ATOMIC_GROUP = getattr(_sre_constants, "ATOMIC_GROUP", None)
# Cap how many copies of a `{n,}` literal body we splice into a run. Posting
# fewer copies than `min` is still a required substring (sound, just looser).
_REPEAT_CHUNK_CAP = 64


def _subpattern_body(av):
    """The nested sre seq of a SUBPATTERN arg, or None."""
    if isinstance(av, (tuple, list)) and len(av) >= 4:
        return av[3]
    return None


def _in_folded_singleton(members) -> "str | None":
    """If every IN member is a LITERAL that case-folds to the same char, that char.

    SigmaHQ writes `[Pp]owershell` and `[pP][oO][wW]...` because YAML `|re` is
    often case-sensitive. Under our CI Teddy needle those classes are one byte.
    RANGE / CATEGORY / NEGATE / mixed letters -> None (not a fixed required char).
    """
    if not members:
        return None
    folded: "str | None" = None
    for item in members:
        if not isinstance(item, (tuple, list)) or len(item) < 2:
            return None
        mop, marg = item[0], item[1]
        if mop is not _OP_LITERAL:
            return None
        ch = chr(marg).lower()
        if folded is None:
            folded = ch
        elif ch != folded:
            return None
    return folded


def _in_literal_members(members) -> "list[str] | None":
    """Chars of an IN that is only distinct LITERALS (not a fold-singleton).

    `[WR]` is two required alternatives after a prefix (`-[WR]` => `-W` or
    `-R`). RANGE / CATEGORY / NEGATE / a fold-singleton (`[Ww]`) -> None;
    fold-singletons splice into the surrounding run via `_in_folded_singleton`.
    """
    if not members:
        return None
    chars: list[str] = []
    for item in members:
        if not isinstance(item, (tuple, list)) or len(item) < 2:
            return None
        mop, marg = item[0], item[1]
        if mop is not _OP_LITERAL:
            return None
        chars.append(chr(marg))
    if len(chars) < 2 or len(chars) > _RE_ALT_MAX:
        return None
    return chars


def _literal_chunk(seq) -> "str | None":
    """Concatenated required chars if *seq* is only literals (and groups of those).

    Accepts LITERAL, case-fold IN singletons, and SUBPATTERN/ATOMIC_GROUP whose
    body is itself a chunk. Anything else (BRANCH, repeat, RANGE, AT, ...) ->
    None, so the caller will not merge across a breaker.
    """
    out: list[str] = []
    for op, av in seq:
        if op is _OP_LITERAL:
            out.append(chr(av))
            continue
        if op is _OP_IN:
            ch = _in_folded_singleton(av)
            if ch is None:
                return None
            out.append(ch)
            continue
        if op is _OP_SUBPATTERN:
            sub = _subpattern_body(av)
            if sub is None:
                return None
            chunk = _literal_chunk(list(sub))
            if chunk is None:
                return None
            out.append(chunk)
            continue
        if _OP_ATOMIC_GROUP is not None and op is _OP_ATOMIC_GROUP:
            sub = av if isinstance(av, (tuple, list)) else None
            if sub is None:
                return None
            chunk = _literal_chunk(list(sub))
            if chunk is None:
                return None
            out.append(chunk)
            continue
        return None
    return "".join(out) if out else None


def _required_literal_runs(seq) -> "list[str]":
    """All literal substrings that EVERY string matching `seq` MUST contain.

    `seq` is a flat list of (opcode, arg) `sre_parse` tokens (a regex AST for one
    concatenation level).  Returns the maximal contiguous runs of REQUIRED literal
    characters, sound necessary factors.  The contract: for any input string `s`
    matched by the regex, every returned run is a substring of `s`.

    Run-building rules (SOUND, conservative, any construct not provably handled
    BREAKS the current run and contributes no literal of its own):

      * LITERAL                      -> append the char to the current run.
      * IN of LITERALS that all case-fold to one char -> that char (SigmaHQ
        `[Pp]owershell` / `[pP][oO][wW]...`). RANGE/CATEGORY/NEGATE break.
      * SUBPATTERN / ATOMIC_GROUP    -> a plain group is required exactly once.
        If the body is a literal chunk it is SPLICED into the current run
        (`(ab)cd` -> `abcd`). Otherwise flush, take the body's own runs, and
        start fresh (alternation / optional inside the group still breaks).
      * MAX/MIN_REPEAT with min>=1 and a literal-chunk body -> append
        `chunk * min` to the current run (`foo+` -> `foo`, `a{3}` -> `aaa`).
        min==0 is optional -> break. A structured body still contributes its
        required runs as separate runs (never merged across the repeat).
      * BRANCH                       -> required iff a literal substring is common
                                        to ALL alternatives.  We compute each
                                        branch's runs, intersect by substring, and
                                        emit any common substring as its OWN run
                                        (it does NOT extend the surrounding run,
                                        since the branch text varies).  If any
                                        branch contributes no run, or the branches
                                        share no >=MIN_LEN substring, the BRANCH
                                        yields nothing AND breaks the run.
      * everything else (IN with RANGE, ANY '.', AT anchors, lookaround,
        GROUPREF, NOT_LITERAL, CATEGORY, min==0 repeats, ...) -> BREAK the
        current run and contribute nothing.
    """
    runs: list[str] = []
    cur: list[str] = []

    def _flush() -> None:
        if cur:
            runs.append("".join(cur))
            cur.clear()

    def _splice_or_runs(body) -> None:
        chunk = _literal_chunk(list(body))
        if chunk:
            cur.append(chunk)
            return
        _flush()
        runs.extend(_required_literal_runs(list(body)))

    for op, av in seq:
        if op is _OP_LITERAL:
            cur.append(chr(av))
            continue
        if op is _OP_IN:
            ch = _in_folded_singleton(av)
            if ch is not None:
                cur.append(ch)
                continue
            _flush()
            continue
        if op is _OP_SUBPATTERN:
            sub = _subpattern_body(av)
            if sub is None:
                _flush()
                continue
            _splice_or_runs(sub)
            continue
        if _OP_ATOMIC_GROUP is not None and op is _OP_ATOMIC_GROUP:
            sub = av if isinstance(av, (tuple, list)) else None
            if sub is None:
                _flush()
                continue
            _splice_or_runs(sub)
            continue
        if op is _OP_MAX_REPEAT or op is _OP_MIN_REPEAT:
            try:
                mn, _mx, item = av[0], av[1], av[2]
            except (TypeError, ValueError, IndexError):
                _flush()
                continue
            body = list(item) if item is not None else []
            chunk = _literal_chunk(body) if body else None
            if mn >= 1 and chunk:
                cur.append(chunk * min(int(mn), _REPEAT_CHUNK_CAP))
                continue
            _flush()
            if mn >= 1 and body:
                runs.extend(_required_literal_runs(body))
            continue
        if op is _OP_BRANCH:
            _flush()
            common = _branch_common_literal(av)
            if common:
                runs.append(common)
            continue
        # Any other opcode is a run-breaker that contributes no fixed literal.
        _flush()
    _flush()
    return runs


def _branch_common_literal(branch_arg) -> "str | None":
    """A case-folded literal substring common to ALL alternatives of a BRANCH,
    or None.  branch_arg = (None, [alt0_seq, alt1_seq, ...]).

    Each alternative's required-literal runs are computed recursively; we then
    take literal substrings (>=MIN_LEN) that appear in at least one run of EVERY
    alternative.  The longest such common substring is returned (case-folded).
    If any alternative has NO run, there is no common required literal -> None
    (sound: that alternative could match with no literal present).
    """
    alts = branch_arg[1] if isinstance(branch_arg, (tuple, list)) and len(branch_arg) >= 2 else None
    if not alts:
        return None
    per_alt_substrs: list[set[str]] = []
    for alt in alts:
        alt_runs = _required_literal_runs(list(alt))
        if not alt_runs:
            return None  # this branch can match with no required literal
        subs: set[str] = set()
        for run in alt_runs:
            folded = run.lower()
            for i in range(len(folded)):
                for j in range(i + 1, len(folded) + 1):
                    sub = folded[i:j]
                    if _prefilter_needle_ok(sub):
                        subs.add(sub)
        if not subs:
            return None  # all runs too short -> no usable common literal
        per_alt_substrs.append(subs)
    common = set.intersection(*per_alt_substrs)
    if not common:
        return None
    return max(common, key=len)


def _regex_anchor(pattern: str) -> "str | None":
    """The longest SOUND, case-folded literal anchor (>=MIN_LEN) for an ERE/PCRE
    `pattern`, or None when no literal is provably present in every match.

    SOUND by construction (see _required_literal_runs): the returned string is a
    substring of EVERY input the regex matches, so requiring it in the event's
    searchable text never prunes a real match (the C verify still runs regexec).
    Folding the anchor for the LUT can only OVER-select candidates (then regexec
    rejects), sound; the regex's own case-sensitivity is enforced by regexec.
    Returns None on ANY parse failure (untrusted corpus) -> always-verify.
    """
    try:
        ast = _sre_parse.parse(pattern)
    except Exception:
        return None
    runs = _required_literal_runs(list(ast))
    best: str | None = None
    for run in runs:
        folded = run.lower()
        if _prefilter_needle_ok(folded) and (
            best is None or len(folded.encode("utf-8")) > len(best.encode("utf-8"))
        ):
            best = folded
    return best


def _try_emit_or_needles(needles: list[str], clauses: list) -> bool:
    """Append one OR clause if every needle is postable. Else False (no emit)."""
    folded: list[str] = []
    for n in needles:
        f = n.lower()
        if not _prefilter_needle_ok(f):
            return False
        folded.append(f)
    if folded:
        clauses.append(frozenset(folded))
    return True


def _prefix_alt_needles(prefix: str, seq) -> "list[str] | None":
    """Spliced needles if *seq* is an IN-of-literals or a BRANCH of literal alts.

    `-[WR]` with prefix `-` -> `['-W', '-R']`. `(curl|wget)` with empty prefix
    -> `['curl', 'wget']`. RANGE / `.+` / a literalless alt -> None.
    """
    tokens = list(seq)
    while tokens and _is_any_star(tokens[0]):
        tokens = tokens[1:]
    while tokens and _is_any_star(tokens[-1]):
        tokens = tokens[:-1]
    if len(tokens) == 1 and tokens[0][0] is _OP_SUBPATTERN:
        sub = _subpattern_body(tokens[0][1])
        if sub is not None:
            tokens = list(sub)
    if not tokens:
        return None
    if len(tokens) == 1 and tokens[0][0] is _OP_IN:
        members = _in_literal_members(tokens[0][1])
        if members is None:
            return None
        return [prefix + m for m in members]
    if len(tokens) == 1 and tokens[0][0] is _OP_BRANCH:
        arg = tokens[0][1]
        alts = arg[1] if isinstance(arg, (tuple, list)) and len(arg) >= 2 else None
        if not alts or len(alts) < 2 or len(alts) > _RE_ALT_MAX:
            return None
        out: list[str] = []
        for alt in alts:
            chunk = _literal_chunk(list(alt))
            if not chunk:
                return None
            out.append(prefix + chunk)
        return out
    return None


def _regex_seq_cnf(seq) -> "list[frozenset[str]]":
    """CNF of prefilter needles for one regex concatenation. Empty = unconstrained.

    AND across returned clauses, OR inside a clause. A prefix spliced onto a
    class or BRANCH (`-[WR]`, `(curl|wget)`) is one OR clause; a required run
    (`powershell` in `powershell.*-enc`) is one AND clause. Constructs that
    donate no postable needle are skipped (they never invent a constraint).
    """
    clauses: list[frozenset[str]] = []
    cur: list[str] = []
    tokens = list(seq)
    while tokens and _is_any_star(tokens[0]):
        tokens = tokens[1:]
    while tokens and _is_any_star(tokens[-1]):
        tokens = tokens[:-1]

    def flush_and() -> None:
        folded = "".join(cur).lower()
        cur.clear()
        if _prefilter_needle_ok(folded):
            clauses.append(frozenset({folded}))

    for op, av in tokens:
        if op is _OP_LITERAL:
            cur.append(chr(av))
            continue
        if op is _OP_IN:
            ch = _in_folded_singleton(av)
            if ch is not None:
                cur.append(ch)
                continue
            needles = _prefix_alt_needles("".join(cur), [(op, av)])
            if needles and _try_emit_or_needles(needles, clauses):
                cur.clear()
                continue
            flush_and()
            continue
        if op is _OP_SUBPATTERN:
            sub = _subpattern_body(av)
            if sub is None:
                flush_and()
                continue
            chunk = _literal_chunk(list(sub))
            if chunk:
                cur.append(chunk)
                continue
            needles = _prefix_alt_needles("".join(cur), sub)
            if needles and _try_emit_or_needles(needles, clauses):
                cur.clear()
                continue
            flush_and()
            clauses.extend(_regex_seq_cnf(list(sub)))
            continue
        if _OP_ATOMIC_GROUP is not None and op is _OP_ATOMIC_GROUP:
            sub = av if isinstance(av, (tuple, list)) else None
            if sub is None:
                flush_and()
                continue
            chunk = _literal_chunk(list(sub))
            if chunk:
                cur.append(chunk)
                continue
            needles = _prefix_alt_needles("".join(cur), sub)
            if needles and _try_emit_or_needles(needles, clauses):
                cur.clear()
                continue
            flush_and()
            clauses.extend(_regex_seq_cnf(list(sub)))
            continue
        if op is _OP_BRANCH:
            needles = _prefix_alt_needles("".join(cur), [(op, av)])
            if needles and _try_emit_or_needles(needles, clauses):
                cur.clear()
                continue
            flush_and()
            continue
        if op is _OP_MAX_REPEAT or op is _OP_MIN_REPEAT:
            try:
                mn, _mx, item = av[0], av[1], av[2]
            except (TypeError, ValueError, IndexError):
                flush_and()
                continue
            body = list(item) if item is not None else []
            chunk = _literal_chunk(body) if body else None
            if int(mn) >= 1 and chunk:
                cur.append(chunk * min(int(mn), _REPEAT_CHUNK_CAP))
                continue
            flush_and()
            if int(mn) >= 1 and body:
                clauses.extend(_regex_seq_cnf(body))
            continue
        flush_and()
    flush_and()
    return clauses


def _regex_cnf(pattern: str) -> "list[frozenset[str]]":
    """CNF of sound prefilter needles for a regex, or empty (always-verify)."""
    try:
        ast = _sre_parse.parse(pattern)
    except Exception:
        return []
    return _regex_seq_cnf(list(ast))


def _regex_literal_body(seq, ignorecase: bool) -> "str | None":
    """Concatenated required chars if *seq* is exactly a literal string.

    Unlike `_literal_chunk` this refuses anything that is not equivalent to
    those chars: a capturing group of literals is fine (`(ab)cd` -> `abcd`);
    a group with extra flags, a class that is not a case-fold singleton under
    IGNORECASE, a repeat, a branch, or an anchor is not.
    """
    out: list[str] = []
    for op, av in seq:
        if op is _OP_LITERAL:
            out.append(chr(av))
            continue
        if op is _OP_IN:
            if not ignorecase:
                return None
            ch = _in_folded_singleton(av)
            if ch is None:
                return None
            out.append(ch)
            continue
        if op is _OP_SUBPATTERN:
            if not isinstance(av, (tuple, list)) or len(av) < 4:
                return None
            add_flags = av[1]
            if add_flags:
                return None
            sub = _regex_literal_body(list(av[3]), ignorecase)
            if sub is None:
                return None
            out.append(sub)
            continue
        if _OP_ATOMIC_GROUP is not None and op is _OP_ATOMIC_GROUP:
            sub = av if isinstance(av, (tuple, list)) else None
            if sub is None:
                return None
            chunk = _regex_literal_body(list(sub), ignorecase)
            if chunk is None:
                return None
            out.append(chunk)
            continue
        return None
    return "".join(out) if out else None


def _regex_as_string_op(
    pattern: str, *, ignorecase: bool = False, multiline: bool = False,
) -> "tuple[int, str, bool] | None":
    """If *pattern* is exactly a string predicate, `(op, literal, case_sensitive)`.

    Equivalence, not a prefilter witness: CONTAINS/EQ/STARTSWITH/ENDSWITH of
    the literal must match the same strings the regex matches. Character
    classes (unless IGNORECASE fold-singletons), wildcards, word boundaries,
    lookaround, and multiline `^`/`$` stay Op.RE so we never over-match.
    """
    try:
        ast = _sre_parse.parse(pattern)
    except Exception:
        return None
    flags = getattr(getattr(ast, "state", None), "flags", 0) or 0
    ic = ignorecase or bool(flags & _SRE_IGNORECASE)
    ml = multiline or bool(flags & _SRE_MULTILINE)
    return _regex_seq_as_string_op(list(ast), ignorecase=ic, multiline=ml)


def _is_any_star(tok) -> bool:
    """True for `.*` / `.{0,}` (zero-or-more ANY). `foo.+` is not this."""
    op, av = tok[0], tok[1]
    if op not in (_OP_MAX_REPEAT, _OP_MIN_REPEAT):
        return False
    try:
        mn, _mx, item = av[0], av[1], av[2]
    except (TypeError, ValueError, IndexError):
        return False
    if int(mn) != 0:
        return False
    body = list(item) if item is not None else []
    return len(body) == 1 and body[0][0] is _OP_ANY


def _regex_seq_as_string_op(
    seq, *, ignorecase: bool, multiline: bool,
) -> "tuple[int, str, bool] | None":
    """`_regex_as_string_op` over an already-parsed sre token list."""
    start = False
    end = False
    body_seq = list(seq)
    if body_seq and body_seq[0][0] is _OP_AT:
        if body_seq[0][1] not in _AT_START:
            return None
        start = True
        body_seq = body_seq[1:]
    if body_seq and body_seq[-1][0] is _OP_AT:
        if body_seq[-1][1] not in _AT_STOP:
            return None
        end = True
        body_seq = body_seq[:-1]
    if any(op is _OP_AT for op, _av in body_seq):
        return None
    if multiline and (start or end):
        return None
    # `foo.*` / `.*foo` / `.*foo.*` are the same string op as `foo`.
    # `foo.+` (min>=1) stays Op.RE.
    while body_seq and _is_any_star(body_seq[0]):
        body_seq = body_seq[1:]
    while body_seq and _is_any_star(body_seq[-1]):
        body_seq = body_seq[:-1]
    lit = _regex_literal_body(body_seq, ignorecase)
    if not lit:
        return None
    if start and end:
        op = Op.EQ
    elif start:
        op = Op.STARTSWITH
    elif end:
        op = Op.ENDSWITH
    else:
        op = Op.CONTAINS
    return op, lit, (not ignorecase)


def _regex_branch_string_ops(
    pattern: str, *, ignorecase: bool = False, multiline: bool = False,
) -> "list[tuple[int, str, bool]] | None":
    """If *pattern* is a BRANCH of string-equivalent alts, one lowered op each.

    `foo|bar`, `(foo|bar)`, `^foo$|^bar$`, `(foo|bar).*`. Any alt that is
    not a string predicate (class, `.+`, lookaround) keeps the whole leaf
    as Op.RE. A wrapping `.*` is the same unanchored CONTAINS as the branch
    without it (`_regex_seq_as_string_op` already strips per-alt `.*`).
    """
    try:
        ast = _sre_parse.parse(pattern)
    except Exception:
        return None
    flags = getattr(getattr(ast, "state", None), "flags", 0) or 0
    ic = ignorecase or bool(flags & _SRE_IGNORECASE)
    ml = multiline or bool(flags & _SRE_MULTILINE)
    seq = list(ast)
    while seq and _is_any_star(seq[0]):
        seq = seq[1:]
    while seq and _is_any_star(seq[-1]):
        seq = seq[:-1]
    if len(seq) == 1 and seq[0][0] is _OP_SUBPATTERN:
        av = seq[0][1]
        if not isinstance(av, (tuple, list)) or len(av) < 4 or av[1]:
            return None
        seq = list(av[3])
    # `^foo$|^bar$` factors a shared `^` out of the BRANCH (AT then BRANCH).
    shared_start: list = []
    shared_end: list = []
    if seq and seq[0][0] is _OP_AT and seq[0][1] in _AT_START:
        shared_start = [seq[0]]
        seq = seq[1:]
    if seq and seq[-1][0] is _OP_AT and seq[-1][1] in _AT_STOP:
        shared_end = [seq[-1]]
        seq = seq[:-1]
    if not (len(seq) == 1 and seq[0][0] is _OP_BRANCH):
        return None
    alts = seq[0][1][1] if isinstance(seq[0][1], (tuple, list)) and len(seq[0][1]) >= 2 else None
    if not alts or len(alts) < 2 or len(alts) > _RE_ALT_MAX:
        return None
    out: list[tuple[int, str, bool]] = []
    for alt in alts:
        one = _regex_seq_as_string_op(
            shared_start + list(alt) + shared_end, ignorecase=ic, multiline=ml,
        )
        if one is None:
            return None
        out.append(one)
    return out


from .pipeline import (
    ecs_pipeline,
    apply_rule_taxonomy,
    TaxonomyError,
)
from .logsource import (  # noqa: F401
    ALWAYS_VERIFY,
    _LOGSOURCE_CATEGORY,
    bucket_keys_for_logsource,
    sigma_category_tokens_for_ecs,
)
from .correlation import (
    CorrelationRule,
    extract_correlation,
    extract_beaconing_from_dict,
    extract_temporal_cond_from_dict,
    correlations_to_json,
)

try:  # correlation rules live in a submodule whose path has moved across versions
    from sigma.correlations import SigmaCorrelationRule
except Exception:  # pragma: no cover - optional
    SigmaCorrelationRule = ()  # isinstance(x, ()) is always False


class CompileError(Exception):
    """A rule used a construct outside the supported mmsigma subset."""


def _placeholder_names_in_value(val) -> list[str]:
    """Placeholder names still sitting in a detection-item value, if any.

    Sigma 1.1 only treats ``%name%`` as a placeholder when ``|expand`` ran;
    a bare percent string is a literal and ``contains_placeholder()`` is false.
    """
    names: list[str] = []
    if val is None:
        return names
    if isinstance(val, (list, tuple)):
        for v in val:
            names.extend(_placeholder_names_in_value(v))
        return names
    if SigmaExpansion and isinstance(val, SigmaExpansion):
        for v in val.values or ():
            names.extend(_placeholder_names_in_value(v))
        return names
    if isinstance(val, SigmaString) and val.contains_placeholder():
        for part in val.iter_parts():
            if Placeholder and isinstance(part, Placeholder):
                names.append(part.name)
    return names


def _unresolved_placeholders(rule) -> list[str]:
    """Unique ``|expand`` placeholder names still in *rule*, detection order."""
    seen: set[str] = set()
    out: list[str] = []
    det = getattr(rule, "detection", None)
    dets = getattr(det, "detections", None) or {}
    for d in dets.values():
        for it in getattr(d, "detection_items", []) or []:
            for name in _placeholder_names_in_value(getattr(it, "value", None)):
                if name not in seen:
                    seen.add(name)
                    out.append(name)
    return out


def _apply_placeholder_values(rule, values: dict) -> None:
    """Replace ``|expand`` placeholders from *values* (name -> str/list).

    pySigma's ``ValueListPlaceholderTransformation`` OR-links the list, which
    is the Sigma contract. A missing name raises ``SigmaValueError``; the
    caller turns that into ``CompileError``.
    """
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations.placeholder import (
        ValueListPlaceholderTransformation,
    )

    capped: dict = {}
    for key, raw in values.items():
        lst = list(raw) if isinstance(raw, (list, tuple)) else [raw]
        if len(lst) > _PLACEHOLDER_MAX:
            raise CompileError(
                f"|expand placeholder {key!r} has {len(lst)} values "
                f"(cap {_PLACEHOLDER_MAX})"
            )
        capped[str(key)] = lst
    pipe = ProcessingPipeline(
        name="libsigma-placeholders",
        priority=10,
        vars=capped,
        items=[
            ProcessingItem(
                identifier="libsigma_value_placeholders",
                transformation=ValueListPlaceholderTransformation(),
            )
        ],
    )
    pipe.apply(rule)


def _merge_placeholders(placeholders: dict | None) -> dict:
    """Copy caller placeholder lists. No name is filled in by default.

    An unresolved ``|expand`` name is a compile error for that rule (Sigma 1.1).
    Callers that want a fallback value pass it in ``placeholders``.
    """
    merged: dict = {}
    if not placeholders:
        return merged
    for key, raw in placeholders.items():
        lst = list(raw) if isinstance(raw, (list, tuple)) else [raw]
        lst = [str(x).strip() for x in lst if str(x).strip()]
        if lst:
            merged[str(key)] = lst
    return merged


_LEVELS = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_LEVEL_SCORE = {0: 5, 1: 10, 2: 20, 3: 35, 4: 50}
_VERDICTS = {"alert": Verdict.ALERT, "benign": Verdict.BENIGN, "escalate": Verdict.ESCALATE}
# Informational rules are correlation substrate / CONTEXT, not STRONG alerts.
# Explicit wake_verdict still wins.
_DEFAULT_VERDICT_BY_LEVEL = {"informational": "benign", "info": "benign"}
_CMP = {"GT": Op.GT, "GTE": Op.GTE, "LT": Op.LT, "LTE": Op.LTE}


def _bucket_keys_for_rule(rule: SigmaRule) -> list[str]:
    """Bucket keys for a rule: ECS event.category and/or raw product/service."""
    ls = rule.logsource
    return bucket_keys_for_logsource(ls.category, ls.service, ls.product)


@dataclass
class CompileResult:
    artifact: bytes
    sidecar: dict
    # Compiled correlation rules (Gate D): warm-path-consumable CorrelationRule
    # objects.  Serialise with `correlation_artifact` for the sibling JSON file.
    correlations: list = _dc_field(default_factory=list)
    errors: list = _dc_field(default_factory=list)
    warnings: list = _dc_field(default_factory=list)  # unmapped fields (when kept)
    dropped: list = _dc_field(default_factory=list)   # rules excluded as not relevant
    # Per-rule necessary-literal CNF (rule index -> list of clauses), the input
    # the prefilter index is built from.  Exposed so coverage of the literal
    # index can be audited against a corpus instead of inferred.
    rule_cnf: dict = _dc_field(default_factory=dict)

    @property
    def correlation_artifact(self) -> str:
        """The sibling ``rules.corr.json`` artifact (Gate D), as a JSON string."""
        return correlations_to_json(self.correlations)


def _glob_to_regex(glob: str) -> str:
    """Anchored ERE from a Sigma wildcard string with internal * / ?."""
    out = ["^"]
    for ch in glob:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(_re.escape(ch))
    out.append("$")
    return "".join(out)


def _string_op(val: SigmaString):
    """Map a (possibly wildcarded) SigmaString to (op, literal)."""
    plain = val.to_plain()
    lead = plain.startswith("*")
    trail = plain.endswith("*")
    core = plain[(1 if lead else 0):(len(plain) - 1 if trail else len(plain))]
    if "*" in core or "?" in core:
        return Op.RE, _glob_to_regex(plain)
    if lead and trail:
        return Op.CONTAINS, core
    if lead:
        return Op.ENDSWITH, core
    if trail:
        return Op.STARTSWITH, core
    return Op.EQ, core


# ECS field the mmsigma runtime always resolves to the pristine raw log line
# (from rawmsg when no parser produced it). Fieldless Sigma keyword searches
# lower onto it: "the value appears anywhere in the event".
EVENT_ORIGINAL = "event.original"


def _glob_to_regex_search(glob: str) -> str:
    """UNANCHORED ERE from a Sigma wildcard string (substring search, no ^...$).

    Used for keyword values with an internal wildcard, where the semantic is
    "this pattern occurs somewhere in the raw line", not "the whole line matches".
    """
    out = []
    for ch in glob:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(_re.escape(ch))
    return "".join(out)


def _keyword_op(val: SigmaString):
    """Map a keyword SigmaString to (op, operand) with SUBSTRING semantics.

    A keyword is searched in the whole event, so a bare literal is CONTAINS (not
    EQ) and an internal-wildcard value is an unanchored regex. Leading/trailing
    `*` are redundant for a substring search and are stripped.
    """
    plain = val.to_plain()
    core = plain.strip("*")
    if "*" in core or "?" in core:
        return Op.RE, _glob_to_regex_search(core)
    return Op.CONTAINS, core


def _emit_keyword(b: SigmaDbBuilder, val) -> None:
    """Emit one predicate for a fieldless Sigma keyword value on event.original.

    pySigma delivers keyword (fieldless) values as ConditionValueExpression whose
    `.value` is a SigmaString or SigmaNumber; the mmsigma runtime always resolves
    event.original to the raw line, so a keyword is a substring search over it.
    """
    if isinstance(val, SigmaString):
        op, operand = _keyword_op(val)
        b.pred(EVENT_ORIGINAL, op, value_id=b.value(operand))
    elif isinstance(val, SigmaNumber):
        b.pred(EVENT_ORIGINAL, Op.CONTAINS, value_id=b.value(str(val.number)))
    else:
        raise CompileError(f"unsupported keyword value {type(val).__name__}")


def _keyword_needle(val) -> "str | None":
    """The sound prefilter needle for a keyword value (see _value_needle)."""
    if not isinstance(val, SigmaString):
        return None
    op, operand = _keyword_op(val)
    if op is Op.RE:
        return _regex_anchor(operand)
    operand = operand.strip()
    folded = operand.lower()
    return folded if _prefilter_needle_ok(folded) else None


def _flatten_expansion(val) -> list:
    """Concrete values of a SigmaExpansion, recursively.

    pySigma emits SigmaExpansion for |windash and |base64offset. The contract
    (sigma.types.SigmaExpansion) is: the variants are OR-linked, even when the
    enclosing list is |all. Nested expansions (a later modifier applied to each
    variant) flatten the same way. A non-expansion value is returned as a
    one-element list so callers can always iterate.
    """
    if isinstance(val, SigmaExpansion):
        out: list = []
        for v in val.values or ():
            out.extend(_flatten_expansion(v))
        if len(out) > _EXPANSION_MAX:
            raise CompileError(
                f"SigmaExpansion has {len(out)} variants (cap {_EXPANSION_MAX})"
            )
        return out
    return [val]


def _emit_value_sel(b: SigmaDbBuilder, field, val, sel_base: int, rpn: list) -> None:
    """One single-predicate selection for (field, val), then a SEL token."""
    ps = b.begin_sel()
    if field is None:
        _emit_keyword(b, val)
    else:
        _emit_leaf(b, SimpleNamespace(field=field, value=val))
    sid = b.end_sel(ps)
    rpn.append((int(CTok.SEL), sid - sel_base))


def _walk_values(b: SigmaDbBuilder, field, vals: list, sel_base: int, rpn: list) -> None:
    """Emit vals as one leaf, or as an RPN OR of leaves when there are several.

    Empty expansion is a compile error (a modifier produced no variant). A
    single value is the ordinary one-pred selection. Several values are the
    SigmaExpansion OR-group.
    """
    if not vals:
        raise CompileError("empty SigmaExpansion")
    _emit_value_sel(b, field, vals[0], sel_base, rpn)
    for v in vals[1:]:
        _emit_value_sel(b, field, v, sel_base, rpn)
        rpn.append((int(CTok.OR), 0))


def _emit_leaf(b: SigmaDbBuilder, node: ConditionFieldEqualsValueExpression) -> None:
    """Append exactly one predicate (a single-pred selection) for a leaf."""
    fld = node.field
    val = node.value

    if fld is None:
        # Defensive: a fieldless leaf that arrives as ConditionFieldEqualsValue
        # (keywords normally arrive as ConditionValueExpression, handled in _walk).
        _emit_keyword(b, val)
        return

    if isinstance(val, SigmaExists):
        b.pred(fld, Op.EXISTS, flags=0 if val.exists else PF_NEGATE)
    elif isinstance(val, SigmaNull):
        b.pred(fld, Op.EXISTS, flags=PF_NEGATE)               # field is null => not exists
    elif isinstance(val, SigmaCIDRExpression):
        net = val.network
        fam = 4 if net.version == 4 else 6
        b.pred(fld, Op.CIDR, value_id=b.cidr(fam, net.prefixlen, net.network_address.packed))
    elif isinstance(val, SigmaCompareExpression):
        op = _CMP.get(val.op.name)
        if op is None:
            raise CompileError(f"unsupported compare op {val.op.name}")
        b.pred(fld, op, ival=int(val.number.number))
    elif isinstance(val, SigmaRegularExpression):
        # Exact Sigma |re semantics: case-SENSITIVE by default, |re|i is
        # case-insensitive, |re|m / |re|s set multiline / dotall. A pattern
        # that is exactly a string predicate is lowered to EQ/CONTAINS/
        # STARTSWITH/ENDSWITH so the matcher never pays pcre2_match for it.
        # Character classes, wildcards, and multiline anchors stay Op.RE.
        names = {getattr(f, "name", "") for f in (getattr(val, "flags", None) or ())}
        pat = str(val.regexp)
        ignorecase = "IGNORECASE" in names
        lowered = _regex_as_string_op(
            pat, ignorecase=ignorecase, multiline="MULTILINE" in names,
        )
        if lowered is not None:
            op, lit, case_sensitive = lowered
            flags = PF_CASE if case_sensitive else 0
            b.pred(fld, op, value_id=b.value(lit), flags=flags)
            return
        alts = _regex_branch_string_ops(
            pat, ignorecase=ignorecase, multiline="MULTILINE" in names,
        )
        if alts is not None:
            for op, lit, case_sensitive in alts:
                flags = PF_CASE if case_sensitive else 0
                b.pred(fld, op, value_id=b.value(lit), flags=flags, group=0)
            return
        inline = "".join(c for c, n in (("m", "MULTILINE"), ("s", "DOTALL")) if n in names)
        if inline:
            pat = f"(?{inline})" + pat
        flags = 0 if ignorecase else PF_CASE
        b.pred(fld, Op.RE, value_id=b.value(pat), flags=flags)
    elif isinstance(val, SigmaFieldReference):
        # |fieldref: compare this field to ANOTHER field's value. Emit a pred whose
        # operand indexes the referenced field (PF_FIELDREF) rather than a literal;
        # the runtime resolves both fields and compares. The referenced field name
        # is already ECS-mapped by the pipeline. Plain fieldref is equality; newer
        # pySigma may expose partial (starts/ends/contains) fieldref -> map it.
        op = Op.EQ
        if getattr(val, "starts_with", False):
            op = Op.STARTSWITH
        elif getattr(val, "ends_with", False):
            op = Op.ENDSWITH
        elif getattr(val, "contains", False):
            op = Op.CONTAINS
        b.pred(fld, op, value_id=b.field(val.field), flags=PF_FIELDREF)
    elif isinstance(val, SigmaString):
        op, lit = _string_op(val)
        # |cased -> case-SENSITIVE compare (SIGMA_PF_CASE). Sigma string ops are
        # case-insensitive by default; a cased string opts into exact case, which
        # the runtime supports (SIGMA_PF_CASE) but which was previously never
        # emitted, so every match silently ran case-insensitive.
        flags = PF_CASE if isinstance(val, SigmaCasedString) else 0
        b.pred(fld, op, value_id=b.value(lit), flags=flags)
    elif isinstance(val, SigmaNumber):
        # Unquoted YAML numbers are numeric equality in Sigma (not a string
        # compare). Emit GTE AND LTE on the same integer so `field: 80`
        # matches "80" and "80/tcp" (sg_to_i64) but not "8000".
        raw = getattr(val, "number", val)
        try:
            n = int(raw)
        except (TypeError, ValueError):
            b.pred(fld, Op.EQ, value_id=b.value(str(val)))
            return
        if float(raw) != float(n):
            b.pred(fld, Op.EQ, value_id=b.value(str(val)))
            return
        b.pred(fld, Op.GTE, ival=n, group=0)
        b.pred(fld, Op.LTE, ival=n, group=1)
    else:
        raise CompileError(f"unsupported value type {type(val).__name__}")


# Verify-path cost for AND/OR operand order. Cheap first: AND skips the rest
# on the first false, OR skips the rest on the first true. The matcher RPN
# short-circuits the right operand; this only decides which operand is left.
_COST_EQ = 1
_COST_AFFIX = 10
_COST_CONTAINS = 20
_COST_RE = 100


def _op_cost(op: int) -> int:
    if op == Op.RE:
        return _COST_RE
    if op == Op.CONTAINS:
        return _COST_CONTAINS
    if op in (Op.STARTSWITH, Op.ENDSWITH):
        return _COST_AFFIX
    return _COST_EQ


def _value_cost(val, keyword: bool = False) -> int:
    """Relative verify cost of one concrete value (after |re lowering)."""
    if isinstance(val, SigmaRegularExpression):
        names = {getattr(f, "name", "") for f in (getattr(val, "flags", None) or ())}
        lowered = _regex_as_string_op(
            str(val.regexp),
            ignorecase="IGNORECASE" in names,
            multiline="MULTILINE" in names,
        )
        if lowered is not None:
            return _op_cost(lowered[0])
        alts = _regex_branch_string_ops(
            str(val.regexp),
            ignorecase="IGNORECASE" in names,
            multiline="MULTILINE" in names,
        )
        if alts is not None:
            return min(_op_cost(op) for op, _lit, _cs in alts)
        return _COST_RE
    if isinstance(val, SigmaString):
        op, _lit = _keyword_op(val) if keyword else _string_op(val)
        return _op_cost(op)
    return _COST_EQ


def _node_cost(node) -> int:
    """Relative verify cost of a condition subtree (cheap = small)."""
    if isinstance(node, ConditionFieldEqualsValueExpression):
        vals = _flatten_expansion(node.value)
        if not vals:
            return _COST_RE
        costs = [_value_cost(v, keyword=False) for v in vals]
        return min(costs)
    if isinstance(node, ConditionValueExpression):
        vals = _flatten_expansion(node.value)
        if not vals:
            return _COST_RE
        costs = [_value_cost(v, keyword=True) for v in vals]
        return min(costs)
    if isinstance(node, ConditionNOT):
        return _node_cost(node.args[0])
    if isinstance(node, ConditionAND):
        return max((_node_cost(a) for a in node.args), default=_COST_EQ)
    if isinstance(node, ConditionOR):
        return min((_node_cost(a) for a in node.args), default=_COST_EQ)
    return _COST_RE


def _walk(node, b: SigmaDbBuilder, sel_base: int, rpn: list) -> None:
    if isinstance(node, ConditionFieldEqualsValueExpression):
        _walk_values(b, node.field, _flatten_expansion(node.value), sel_base, rpn)
    elif isinstance(node, ConditionValueExpression):
        # Fieldless Sigma keyword: substring predicate(s) on event.original.
        _walk_values(b, None, _flatten_expansion(node.value), sel_base, rpn)
    elif isinstance(node, ConditionNOT):
        _walk(node.args[0], b, sel_base, rpn)
        rpn.append((int(CTok.NOT), 0))
    elif isinstance(node, (ConditionAND, ConditionOR)):
        joiner = int(CTok.AND) if isinstance(node, ConditionAND) else int(CTok.OR)
        args = sorted(node.args, key=_node_cost)
        if not args:
            raise CompileError("empty boolean node")
        _walk(args[0], b, sel_base, rpn)
        for a in args[1:]:
            _walk(a, b, sel_base, rpn)
            rpn.append((joiner, 0))
    else:
        raise CompileError(f"unsupported condition node {type(node).__name__}")


# ----------------------------------------------------------------------------
# ADR-0072 P2: required-literal (prefilter) extraction.
#
# Walk the SAME parsed condition tree as _walk and return the rule's necessary-
# literal CNF: a list of CLAUSES, each clause a frozenset of (field, needle)
# pairs (field None = a fieldless keyword, i.e. event.original), with the
# soundness contract
#
#     rule matches event  ==>  every clause has >=1 of its needles present
#                              in the named field of the event.
#
# The field tag is what lets a consumer scope a needle to the field whose
# predicate required it; dropping it (as the v3 artifact does) is sound but
# looser, since a needle occurring in any field then keeps the rule.
#
# An empty CNF ([]) means "no sound required literal" -> the rule is ALWAYS-VERIFY
# (never prefiltered out).  A clause that would be empty (a disjunction branch
# with no sound literal) collapses the surrounding OR to "no constraint", which is
# the sound behaviour (we must not invent a constraint that could prune a real
# match).  When in doubt we return [] (always-verify): a wrongly-pruned rule is a
# MISSED DETECTION (cf. the turbo prefix-rule bug), a wrongly-kept candidate just
# costs one extra verify.
# ----------------------------------------------------------------------------
def _value_needle(field, val) -> "str | None":
    """The case-folded required-literal substring of a positive string leaf, or
    None when the leaf carries no sound prefilter literal (numeric/cidr/exists/
    null, a negated leaf, or a literal-less/too-short pattern).

    For EQ the whole value equals the literal, so the literal is a substring of
    the value; for CONTAINS/STARTSWITH/ENDSWITH the literal is a substring by
    definition. In every case "literal bytes present in the field value" is a
    NECESSARY condition for the leaf to be true, hence sound to prefilter on.

    A regex leaf, either an explicit `|re` (SigmaRegularExpression) or a
    wildcard SigmaString that _string_op mapped to Op.RE, gets a sound literal
    ANCHOR extracted from the regex AST (a substring EVERY match must contain)
    when one exists; otherwise None (always-verify). The C verify still runs
    regexec, so the anchor only restricts candidacy, never the final match.
    """
    if field is None:
        return _keyword_needle(val)
    if isinstance(val, SigmaRegularExpression):
        # Explicit |re predicate: extract a necessary literal factor from the AST.
        return _regex_anchor(str(val.regexp))
    if not isinstance(val, SigmaString):
        return None  # exists/null/cidr/compare/number -> no sound literal
    op, lit = _string_op(val)
    if op not in _PREFILTER_STR_OPS:
        # Internal-wildcard SigmaString -> Op.RE: extract an anchor from the same
        # anchored ERE the matcher will regexec (sound, often a fixed core token).
        return _regex_anchor(_glob_to_regex(val.to_plain()))
    # Strip YAML padding (`' -enc'`). A value that IS only whitespace
    # (SigmaHQ "Space After Filename": endswith `' '`) becomes empty and
    # stays always-verify: Teddy keys 2-3 bytes, and a space on
    # CommandLine saturates the process bucket anyway.
    lit = lit.strip()
    folded = lit.lower()
    if not _prefilter_needle_ok(folded):
        return None
    return folded  # Sigma string ops default case-insensitive (mirror PF_CASE)


def _leaf_cnf(field, val) -> "list[frozenset[tuple]]":
    """CNF clauses for one concrete leaf value. Empty = unconstrained.

    String/regex leaves post a Teddy needle. Numeric and CIDR leaves post a
    field-witness atom (evaluated by a field lookup, not Teddy). Numeric
    equality is one NUMEQ atom (equivalent to GTE and LTE on integers).
    """
    if isinstance(val, SigmaCompareExpression):
        op = _CMP.get(val.op.name)
        if op is None:
            return []
        try:
            n = int(val.number.number)
        except (TypeError, ValueError, AttributeError):
            return []
        return [frozenset({("n", field, int(op), n)})]
    if isinstance(val, SigmaNumber):
        raw = getattr(val, "number", val)
        try:
            n = int(raw)
        except (TypeError, ValueError):
            return []
        if float(raw) != float(n):
            return []
        return [frozenset({("n", field, int(Op.NUMEQ), n)})]
    if isinstance(val, SigmaCIDRExpression):
        net = val.network
        fam = 4 if net.version == 4 else 6
        packed = net.network_address.packed
        return [frozenset({("c", field, fam, int(net.prefixlen), packed)})]
    if isinstance(val, SigmaRegularExpression):
        names = {getattr(f, "name", "") for f in (getattr(val, "flags", None) or ())}
        alts = _regex_branch_string_ops(
            str(val.regexp),
            ignorecase="IGNORECASE" in names,
            multiline="MULTILINE" in names,
        )
        if alts is not None:
            atoms: set = set()
            for _op, lit, _cs in alts:
                folded = lit.strip().lower()
                if not _prefilter_needle_ok(folded):
                    return []
                atoms.add(("s", field, folded))
            return [frozenset(atoms)] if atoms else []
        clauses = _regex_cnf(str(val.regexp))
        if clauses:
            return [frozenset({("s", field, n) for n in clause}) for clause in clauses]
        return []
    if isinstance(val, SigmaString):
        op, _lit = _string_op(val)
        if op is Op.RE:
            clauses = _regex_cnf(_glob_to_regex(val.to_plain()))
            if clauses:
                return [frozenset({("s", field, n) for n in clause}) for clause in clauses]
            return []
    ndl = _value_needle(field, val)
    return [frozenset({("s", field, ndl)})] if ndl is not None else []


def _cnf_for_values(field, val) -> "list[frozenset[tuple]]":
    """CNF clauses for one leaf, flattening SigmaExpansion as an OR of variants.

    Every variant must contribute a witness; if any variant has none, the
    expansion can match with no posted atom present, so the leaf is
    unconstrained (always-verify). Matches `_walk_values` (OR of selections).
    """
    vals = _flatten_expansion(val)
    if not vals:
        return []
    if len(vals) == 1:
        return _leaf_cnf(field, vals[0])
    union: set = set()
    for v in vals:
        clauses = _leaf_cnf(field, v)
        if not clauses:
            return []
        for clause in clauses:
            union |= clause
    return [frozenset(union)] if union else []


def _rule_cnf(node) -> "list[frozenset[tuple]]":
    """Necessary-literal CNF for a condition (sub)tree (see contract above)."""
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _cnf_for_values(node.field, node.value)
    if isinstance(node, ConditionValueExpression):
        # Fieldless keyword leaf: its substring is a necessary literal.
        return _cnf_for_values(None, node.value)
    if isinstance(node, ConditionNOT):
        # Negation breaks the necessary-literal guarantee (the inner literal
        # being ABSENT is what makes a NOT true). Process-ghosting rules
        # (`not Image|contains: '\'`) have no positive needle and stay
        # always-verify; a negative witness would need a format bump.
        return []
    if isinstance(node, ConditionAND):
        # AND: every child must be true -> every child's clauses are necessary.
        # Concatenate the children's CNFs (children with no constraint contribute
        # nothing, which is sound, they simply don't tighten the prefilter).
        out: list[frozenset[tuple]] = []
        for a in node.args:
            out.extend(_rule_cnf(a))
        return out
    if isinstance(node, ConditionOR):
        # OR: at least one child true.  A single sound clause is the UNION of each
        # child's needles: if the OR is true some child is true, so that child's
        # (non-empty) clauses all hold and at least one of its needles is present,
        # which lies in the union.  BUT if ANY child has an empty CNF (no
        # constraint, e.g. a regex/negated branch) the OR could be satisfied with
        # NO literal present, so the whole OR carries no sound constraint -> [].
        union: set = set()
        for a in node.args:
            child = _rule_cnf(a)
            if not child:
                return []  # an unconstrained branch -> OR is unconstrained (sound)
            for clause in child:
                union |= clause
        return [frozenset(union)] if union else []
    # Unknown node kind: conservatively unconstrained (always-verify).
    return []


def _mitre_all(rule) -> list[str]:
    """Every ``attack.t*`` tag as a T-id, tag order preserved."""
    out: list[str] = []
    for t in getattr(rule, "tags", None) or []:
        s = str(t)
        if s.startswith("attack.t"):
            out.append(s[len("attack."):].upper())
    return out


def _mitre(rule: SigmaRule):
    """The rule's PRIMARY MITRE technique T-id, or None.

    Tie-break (deterministic): the FIRST ``attack.t<id>`` tag in the rule's tag
    order.  SigmaHQ convention lists the primary technique tag first; a rule may
    carry several. The binary still carries only the primary (TAC join-key);
    the sidecar lists every technique as ``mitre_all``.
    """
    all_t = _mitre_all(rule)
    return all_t[0] if all_t else None


def _status_token(rule) -> str:
    st = getattr(rule, "status", None)
    if st is None:
        return ""
    name = getattr(st, "name", None)
    return (name or str(st)).strip().lower()


def _status_skip_reason(rule, *, keep_deprecated: bool) -> str | None:
    """Why this rule is skipped for status, or None to compile it."""
    if keep_deprecated:
        return None
    tok = _status_token(rule)
    if tok in _STATUS_SKIP:
        return f"status {tok}"
    return None


def compile_rules(source, *,
                  keep_deprecated: bool = False,
                  placeholders: "dict | None" = None,
                  ecs: bool = True,
                  gate=None,
                  warn=None,
                  field_ok=None,
                  beaconing_docs: "list | None" = None,
                  sep198_docs: "list | None" = None) -> CompileResult:
    """Compile Sigma YAML (str) or a SigmaCollection into a CompileResult.

    Every rule that parses is compiled. Field names are emitted as written
    after the optional ECS rename (``ecs=True``, the default). A deployment
    that wants to drop rules for fields it does not produce passes ``gate``.

    * ``ecs=True``: taxonomy ``sigma`` (the default) applies
      :func:`ecs_pipeline`. Taxonomy ``ecs`` skips the rename. Any other
      taxonomy is an error on that rule.
    * ``ecs=False``: names are compiled exactly as written.
    * Status (``keep_deprecated=False``, the default): ``deprecated`` and
      ``unsupported`` rules are dropped with a reason. ``experimental``,
      ``test``, and ``stable`` compile.
    * ``gate(rule, taxonomy)`` returns a drop reason string, or None to keep
      the rule. The callback runs after the rename and after placeholder
      substitution. Dropped rules are recorded in ``dropped``.
    * ``warn(rule, taxonomy, rid)`` returns extra warning dicts. They do not
      change the artifact.
    * ``field_ok(name)`` is consulted for ``taxonomy: ecs`` correlation
      group-by fields. None means every name is accepted.
    * ``|expand`` placeholders come from ``placeholders`` (name to value
      list). A leftover name is an error on that rule. Nothing is invented
      for a missing name.
    """
    if isinstance(source, str):
        source, peeled_b, peeled_s = _peel_raw_corr_docs(source)
        beaconing_docs = list(beaconing_docs or []) + peeled_b
        sep198_docs = list(sep198_docs or []) + peeled_s
    else:
        sep198_docs = list(sep198_docs or [])
        beaconing_docs = list(beaconing_docs or [])
    if isinstance(source, SigmaCollection):
        coll = source
    elif isinstance(source, str) and not source.strip():
        coll = type("_EmptyColl", (), {"rules": []})()
    else:
        coll = SigmaCollection.from_yaml(source)

    placeholders = _merge_placeholders(placeholders)
    b = SigmaDbBuilder()
    pipe = ecs_pipeline() if ecs else None
    sidecar: dict = {}
    correlations: list = []
    errors: list = []
    warnings: list = []
    dropped: list = []
    next_id = 1

    # Gate D: correlation rules may appear before OR after the base rules they
    # reference, so we resolve them in a SECOND pass once every single-event rule
    # has a compiled `rid`.  `name_to_rid` is the join key from a Sigma rule
    # name/title (how a correlation references its base) to the compiled rid (how
    # mmsigma stamps a match under `$!sigma.rules[].id`).
    corr_rules: list = []
    name_to_rid: dict[str, int] = {}
    # ADR-0072: bucket key -> rule INDICES (into b.rules), filled as we compile.
    buckets: dict[str, list[int]] = {}
    # ADR-0072 P2: rule_idx -> necessary-literal CNF (list of frozensets).  An
    # empty CNF marks a rule that has no sound required literal -> always-verify.
    rule_cnf: dict[int, "list[frozenset[tuple]]"] = {}

    for rule in coll.rules:
        if SigmaCorrelationRule and isinstance(rule, SigmaCorrelationRule):
            corr_rules.append(rule)
            continue
        if not isinstance(rule, SigmaRule):
            continue
        try:
            # taxonomy sigma renames to ECS; taxonomy ecs leaves names; other
            # values are an error. ecs=False compiles every name as written.
            if ecs:
                try:
                    tax = apply_rule_taxonomy(rule, pipe)
                except TaxonomyError as exc:
                    raise CompileError(str(exc)) from exc
            else:
                tax = "as-written"

            # |expand: Sigma 1.1 placeholders (%name%) are only placeholders
            # when the expand modifier ran. The spec requires a backend that
            # cannot resolve them to REJECT the rule, not emit the literal
            # "%name%". Resolve from `placeholders` (name -> value list) when
            # given; leftover names are a CompileError.
            if placeholders:
                try:
                    _apply_placeholder_values(rule, placeholders)
                except CompileError:
                    raise
                except Exception as exc:
                    raise CompileError(
                        f"unresolved |expand placeholder: {exc}"
                    ) from exc
            leftover = _unresolved_placeholders(rule)
            if leftover:
                raise CompileError(
                    f"unresolved |expand placeholder(s) {leftover}"
                )

            why = _status_skip_reason(rule, keep_deprecated=keep_deprecated)
            if why:
                dropped.append({
                    "title": rule.title,
                    "uuid": str(rule.id) if rule.id else None,
                    "reason": why,
                })
                continue

            if gate is not None:
                drop_reason = gate(rule, tax)
                if drop_reason:
                    dropped.append({
                        "title": rule.title,
                        "uuid": str(rule.id) if rule.id else None,
                        "reason": drop_reason,
                    })
                    continue

            tree = rule.detection.parsed_condition[0].parse()
            sel_base = len(b.sels)
            rpn: list = []
            _walk(tree, b, sel_base, rpn)
            sel_count = len(b.sels) - sel_base

            lvl_name = rule.level.name.lower() if rule.level is not None else "medium"
            sev = _LEVELS.get(lvl_name, 2)
            attrs = rule.custom_attributes or {}
            raw_verdict = attrs.get("verdict")
            if raw_verdict is None or str(raw_verdict).strip() == "":
                raw_verdict = attrs.get("wake_verdict")
            if raw_verdict is None or str(raw_verdict).strip() == "":
                vstr = _DEFAULT_VERDICT_BY_LEVEL.get(lvl_name, "alert")
            else:
                vstr = str(raw_verdict).lower()
            verdict = _VERDICTS.get(vstr, Verdict.ALERT)

            rid = next_id
            next_id += 1
            # Primary MITRE technique -> binary (Gate A.4): intern the T-id into
            # the .values strpool and reference it from the rule, so mmsigma can
            # emit it in $!sigma.rules[].mitre, the TAC node join-key. Absent
            # technique stays NO_VALUE (not emitted).  The sidecar keeps it too
            # for human-facing display.
            mitre_t = _mitre(rule)
            mitre_all = _mitre_all(rule)
            mitre_id = b.value(mitre_t) if mitre_t else NO_VALUE
            rule_idx = b.rule(rid, sel_base, sel_count, cond=rpn, verdict=int(verdict),
                              severity=sev, score_x100=_LEVEL_SCORE[sev], mitre_id=mitre_id)
            # ADR-0072: assign this rule's table index to every lookup key
            # (ECS category and every product/service token, including linux/windows).
            for bkey in _bucket_keys_for_rule(rule):
                buckets.setdefault(bkey, []).append(rule_idx)
            # ADR-0072 P2: derive the rule's necessary-literal CNF from the SAME
            # parsed tree the matcher's verify path uses (sound by construction).
            try:
                rule_cnf[rule_idx] = _rule_cnf(tree)
            except CompileError:
                # Over-cap / flatten raise belongs in _walk (rule never
                # registered). If CNF ever sees a value emit did not, fall
                # back to always-verify rather than omit the rule from
                # litidx (which would silently never fire).
                rule_cnf[rule_idx] = []
            sidecar[rid] = {
                "uuid": str(rule.id) if rule.id else None,
                "title": rule.title,
                "level": lvl_name,
                "mitre": mitre_t,
                "mitre_all": mitre_all,
                "status": _status_token(rule) or None,
                "verdict": vstr,
            }
            # Gate D join key: a correlation references its base rule by Sigma
            # `name` (or, in some corpora, by `title`); record both -> this rid
            # so the second pass can resolve references to the live-stream id.
            rname = getattr(rule, "name", None)
            if rname:
                name_to_rid[str(rname)] = rid
            if rule.title:
                name_to_rid.setdefault(str(rule.title), rid)
            if rule.id:
                name_to_rid.setdefault(str(rule.id), rid)
            if warn is not None:
                extra = warn(rule, tax, rid) or []
                warnings.extend(extra)
        except Exception as e:
            # Untrusted external corpus: a single rule using a construct
            # pySigma rejects (deprecated pipe/aggregation syntax, unsupported
            # modifier, …) or outside the mmsigma subset (CompileError) must be
            # recorded and skipped, never abort the whole batch.
            errors.append({"title": rule.title, "uuid": str(rule.id) if rule.id else None,
                           "error": f"{type(e).__name__}: {e}"})

    # --- Gate D second pass: resolve correlations against compiled base rules.
    # A correlation whose base rule did not compile (dropped as not-relevant,
    # errored, or omitted by per-node targeting) cannot fire, it is recorded in
    # `dropped` with a reason, NEVER silently discarded (the trust landmine this
    # gate closes: today the compiler RECOGNISES correlations then drops them
    # with zero runtime consumers).
    for rule in corr_rules:
        why = _status_skip_reason(rule, keep_deprecated=keep_deprecated)
        if why:
            dropped.append({
                "title": getattr(rule, "title", None),
                "uuid": str(getattr(rule, "id", "")) or None,
                "reason": why,
            })
            continue
        try:
            corr, drop_rec = extract_correlation(rule, name_to_rid, field_ok=field_ok)
        except Exception as e:  # untrusted corpus, never abort the batch
            errors.append({
                "title": getattr(rule, "title", None),
                "uuid": str(getattr(rule, "id", "")) or None,
                "error": f"{type(e).__name__}: {e}",
            })
            continue
        if corr is not None:
            correlations.append(corr)
        elif drop_rec is not None:
            dropped.append(drop_rec)

    # Beaconing correlations bypassed pySigma (its condition parser rejects our
    # custom cv_permille / n_buckets keys); resolve them from their raw dicts
    # against the SAME name_to_rid join the pySigma correlations used.
    for doc in (sep198_docs or []):
        st = str(doc.get("status") or "").strip().lower()
        if not keep_deprecated and st in _STATUS_SKIP:
            dropped.append({
                "title": doc.get("title") or doc.get("name"),
                "uuid": str(doc.get("id") or "") or None,
                "reason": f"status {st}",
            })
            continue
        try:
            corr, drop_rec = extract_temporal_cond_from_dict(doc, name_to_rid)
        except Exception as e:
            errors.append({
                "title": doc.get("title") or doc.get("name"),
                "uuid": str(doc.get("id") or "") or None,
                "error": f"{type(e).__name__}: {e}",
            })
            continue
        if corr is not None:
            correlations.append(corr)
        elif drop_rec is not None:
            dropped.append(drop_rec)

    for doc in (beaconing_docs or []):
        st = str(doc.get("status") or "").strip().lower()
        if not keep_deprecated and st in _STATUS_SKIP:
            dropped.append({
                "title": doc.get("title") or doc.get("name"),
                "uuid": str(doc.get("id") or "") or None,
                "reason": f"status {st}",
            })
            continue
        try:
            corr, drop_rec = extract_beaconing_from_dict(
                doc, name_to_rid, field_ok=field_ok)
        except Exception as e:  # untrusted corpus, never abort the batch
            errors.append({
                "title": doc.get("title") or doc.get("name"),
                "uuid": str(doc.get("id") or "") or None,
                "error": f"{type(e).__name__}: {e}",
            })
            continue
        if corr is not None:
            correlations.append(corr)
        elif drop_rec is not None:
            dropped.append(drop_rec)

    # Install the logsource/category bucket index.
    # An empty mapping (no rules compiled) leaves it with no bucket index (linear fallback).
    b.set_buckets(buckets)

    # Build the literal prefilter index (litidx) from each rule's whole
    # necessary-atom CNF.  String clauses post Teddy needles; numeric/CIDR
    # clauses post field witnesses.  Each posting carries the FIELD its atom
    # must hold in, so the matcher gates a rule in only once every clause has
    # an atom present in the field that clause names.  A rule with an empty
    # CNF (no sound atom) joins the ALWAYS-VERIFY set and is NEVER prefiltered
    # out.  Both restrictions are necessary conditions, so gating stays SOUND;
    # the full rule still verifies.
    #
    # Clauses are posted most-selective first and capped at MAX_CLAUSES, the
    # matcher's per-rule bitmask width.  Dropping the surplus clauses of a rule
    # that has more only loosens the gate, which is the safe direction.
    needle_refs: dict[str, list[tuple]] = {}
    fwits: list[tuple] = []
    always_verify_rules: list[int] = []
    rule_clause_counts = [0] * len(b.rules)

    def _atom_key(atom: tuple):
        kind = atom[0]
        fld = atom[1] or ""
        if kind == "s":
            return (0, fld, atom[2])
        if kind == "n":
            return (1, fld, atom[2], atom[3])
        return (2, fld, atom[2], atom[3])

    for rule_idx in sorted(rule_cnf):
        cnf = [c for c in rule_cnf[rule_idx] if c]
        if not cnf:
            always_verify_rules.append(rule_idx)
            continue
        clauses = sorted(cnf, key=len)[:MAX_CLAUSES]
        rule_clause_counts[rule_idx] = len(clauses)
        for clause_idx, clause in enumerate(clauses):
            for atom in sorted(clause, key=_atom_key):
                kind = atom[0]
                field = atom[1]
                name = field if field is not None else EVENT_ORIGINAL
                if kind == "s":
                    fid = b.field_id(name)
                    needle_refs.setdefault(atom[2], []).append(
                        (rule_idx, ANY_FIELD if fid is None else fid, clause_idx))
                    continue
                fid = b.field(name)
                if kind == "n":
                    fwits.append((rule_idx, fid, clause_idx, atom[2], atom[3]))
                elif kind == "c":
                    cid = b.cidr(atom[2], atom[3], atom[4])
                    fwits.append((rule_idx, fid, clause_idx, int(Op.CIDR), cid))
    b.set_litidx(needle_refs, always_verify_rules, rule_clause_counts, fwits=fwits)

    return CompileResult(artifact=b.serialize(), sidecar=sidecar,
                         correlations=correlations, errors=errors,
                         warnings=warnings, dropped=dropped, rule_cnf=rule_cnf)


def _peel_raw_corr_docs(text: str):
    """Split a YAML stream into (remainder, beaconing_docs, sep198_docs).

    Beaconing and SEP #198 string-condition temporals are pulled out because
    pySigma's correlation parser rejects their condition objects. Remainder is
    re-dumped for SigmaCollection.from_yaml. Unchanged input is returned as-is
    when nothing was peeled, so the common path does not round-trip YAML.
    """
    try:
        import yaml
        docs = list(yaml.safe_load_all(text))
    except Exception:
        return text, [], []
    kept, bdocs, sdocs = [], [], []
    for d in docs:
        if not isinstance(d, dict):
            if d is not None:
                kept.append(d)
            continue
        corr = d.get("correlation")
        if isinstance(corr, dict):
            t = str(corr.get("type") or "").lower()
            if t == "beaconing":
                bdocs.append(d)
                continue
            if t in ("temporal", "temporal_ordered") and isinstance(corr.get("condition"), str):
                sdocs.append(d)
                continue
        kept.append(d)
    if not bdocs and not sdocs:
        return text, [], []
    remainder = yaml.safe_dump_all(kept) if kept else ""
    return remainder, bdocs, sdocs


def _beaconing_doc(text: str):
    """If `text` is a single-document ``type: beaconing`` correlation, return its
    parsed dict; else None.  Beaconing rules carry a custom ``cv_permille`` /
    ``n_buckets`` condition that pySigma's parser rejects, so the compiler pulls
    these files out of the pySigma path and resolves them from the raw dict
    (see correlation.extract_beaconing_from_dict).  Only single-doc files are
    intercepted; a mixed file falls through to pySigma (and would drop its
    beaconing part), correlation rules ship one-per-file, so this is enough."""
    try:
        import yaml
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except Exception:
        return None
    if len(docs) == 1:
        corr = docs[0].get("correlation")
        if isinstance(corr, dict) and str(corr.get("type") or "").lower() == "beaconing":
            return docs[0]
    return None


def compile_directory(rules_dir, *extra_dirs, keep_deprecated: bool = False,
                      placeholders: "dict | None" = None,
                      ecs: bool = True,
                      gate=None,
                      warn=None,
                      field_ok=None,
                      disabled: "set[str] | None" = None) -> CompileResult:
    """Compile every ``*.yml`` / ``*.yaml`` under ``rules_dir`` (and ``extra_dirs``).

    A missing extra directory is skipped. A file pySigma cannot parse is
    recorded in ``errors`` and the rest of the corpus still compiles.
    ``disabled`` is a set of basenames to skip. ``gate``, ``warn``, and
    ``field_ok`` are forwarded to :func:`compile_rules`.
    """
    import pathlib

    files: list = []
    for raw in (rules_dir, *extra_dirs):
        if raw is None:
            continue
        d = pathlib.Path(raw)
        if not d.is_dir():
            continue
        files.extend(set(d.rglob("*.yml")) | set(d.rglob("*.yaml")))
    files = sorted(set(files))
    # Operator soft-disable: skip rules the operator toggled off (by basename)
    # so a bundled or custom rule stops deploying without being deleted.
    if disabled:
        files = [f for f in files if f.name not in disabled]
    cols = []
    parse_errors: list = []
    beaconing_docs: list = []
    sep198_docs: list = []
    for f in files:
        text = f.read_text(encoding="utf-8")
        remainder, bdocs, sdocs = _peel_raw_corr_docs(text)
        beaconing_docs.extend(bdocs)
        sep198_docs.extend(sdocs)
        if bdocs or sdocs:
            if not remainder.strip():
                continue
            text = remainder
        try:
            # Reference resolution is DEFERRED (resolve_references=False): a Sigma
            # correlation rule references its base rules by `name`, and those base
            # rules almost always live in a DIFFERENT file (a correlation pack is
            # separate from the detections it composes). pySigma's per-file
            # resolver would raise "Rule '<name>' not found in rule collection"
            # and the whole correlation file would be discarded. The Gate-D second
            # pass in compile_rules() owns correlation resolution (name_to_rid ->
            # compiled rid, with a graceful `dropped` record when a base rule did
            # not compile), so pySigma must NOT resolve here.
            cols.append(SigmaCollection.from_yaml(text, resolve_references=False))
        except Exception as exc:  # malformed / unsupported rule file
            parse_errors.append({"title": f.name, "error": f"parse failed: {exc}"})
    if not cols:
        res = CompileResult(artifact=SigmaDbBuilder().serialize(), sidecar={})
        res.errors.extend(parse_errors)
        return res
    # Merge keeps references deferred for the same reason, cross-file base rules
    # are resolved by name in compile_rules(), not by pySigma.
    coll = (SigmaCollection.merge(cols, resolve_references=False)
            if len(cols) > 1 else cols[0])
    res = compile_rules(coll, keep_deprecated=keep_deprecated,
                        placeholders=placeholders, ecs=ecs, gate=gate,
                        warn=warn, field_ok=field_ok,
                        beaconing_docs=beaconing_docs,
                        sep198_docs=sep198_docs)
    res.errors.extend(parse_errors)
    return res
