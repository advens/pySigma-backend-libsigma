# SPDX-License-Identifier: LGPL-2.1-only
"""Byte-exact serializer for the libsigma `.sigmac` artifact.

Mirrors src/sigma_format.h and src/docs/SIGMAC_FORMAT.md. The struct packs
below are deliberately explicit (manual alignment padding) so the bytes match
the C structs exactly on amd64 and aarch64 (both little-endian); the C loader
validates magic/version/size/CRC32C/ranges, so any drift fails loudly.

CRC32C (Castagnoli) is computed identically to sigma_simd.h so the C loader
accepts artifacts produced here.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum

MAGIC = 0x53474D41  # "SGMA"
# The .sigmac artifact carries the logsource/category bucket index AND the SIMD
# literal-prefilter index (litidx): case-folded needles (interned) -> per-needle
# rule-id postings, numeric/CIDR field witnesses, plus an always-verify set of
# rule indices that are NEVER prefiltered out (rules with no sound required
# atom: unconstrained |re / negate / exists / a literal-less OR branch). The
# matcher builds a Teddy multi-pattern matcher from the needle bytes at load
# time and evaluates field witnesses by lookup. Field-NAME strpool entries are
# NUL-terminated so a zero-copy field-resolve callback can hand the strpool
# pointer straight to a C-string lookup (no bounce copy).
VERSION = 5

HDR_SIZE = 144
SZ_STR = 8
SZ_PRED = 24
SZ_SEL = 8
SZ_CTOK = 8
SZ_RULE = 32
SZ_CIDR = 20
SZ_BUCKET = 8        # sigma_bucket_t: u32 idx_start, u32 idx_count
SZ_LITPOST = 8       # sigma_litpost_t: u32 idx_start, u32 idx_count (same shape)
SZ_LITREF = 8        # sigma_litref_t: u32 rule_idx, u16 field_id, u8 clause_idx, u8 pad
SZ_FWIT = 16         # sigma_fwit_t: u32 rule_idx, u16 field_id, u8 clause, u8 op, i64 ival
ANY_FIELD = 0xFFFF   # SIGMA_LITREF_ANY_FIELD: posting not scoped to a field
MAX_CLAUSES = 32     # SIGMA_MAX_CLAUSES: clauses tracked per rule

NO_VALUE = 0xFFFFFFFF
PF_CASE = 0x01
PF_NEGATE = 0x02
# |fieldref: value_id indexes the FIELDS table (the referenced field), not values.
# Mirrors SIGMA_PF_FIELDREF in sigma_match.h.
PF_FIELDREF = 0x04


class Op(IntEnum):
    EQ = 0
    CONTAINS = 1
    STARTSWITH = 2
    ENDSWITH = 3
    EXISTS = 4
    GT = 5
    GTE = 6
    LT = 7
    LTE = 8
    RE = 9
    CIDR = 10
    NUMEQ = 11  # prefilter integer equality (field: 80)


class Verdict(IntEnum):
    ALERT = 0
    BENIGN = 1
    ESCALATE = 2


class CTok(IntEnum):
    SEL = 0
    AND = 1
    OR = 2
    NOT = 3


def crc32c(data: bytes) -> int:
    """CRC32C (poly 0x1EDC6F41, reflected 0x82F63B78), matches sigma_simd.h."""
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if (crc & 1) else (crc >> 1)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


def _align8(x: int) -> int:
    return (x + 7) & ~7


@dataclass
class _Pred:
    field_id: int
    group_id: int
    op: int
    flags: int
    value_id: int
    ival: int


@dataclass
class _Rule:
    rule_id: int
    sel_start: int
    sel_count: int
    cond_start: int
    cond_count: int
    verdict: int
    severity: int
    score_x100: int
    name_id: int
    mitre_id: int


class SigmaDbBuilder:
    """Accumulates fields/values/predicates/selections/conditions/rules/cidrs
    and serializes to a `.sigmac` byte string."""

    def __init__(self) -> None:
        self._pool = bytearray()
        self._field_ids: dict[str, int] = {}
        self.fields: list[tuple[int, int]] = []  # (off, len) into strpool
        self.values: list[tuple[int, int]] = []
        self.preds: list[_Pred] = []
        self.sels: list[tuple[int, int]] = []     # (pred_start, pred_count)
        self.cond: list[tuple[int, int]] = []      # (kind, sel_idx)
        self.rules: list[_Rule] = []
        self.cidrs: list[tuple[int, int, bytes]] = []  # (family, prefix, net16)
        # bucket index: bucket key -> list of rule INDICES (into
        # self.rules).  Built post-hoc via set_buckets(); empty => a no-bucket-index
        # artifact (the C matcher falls back to a full linear scan).
        self._bucket_keys: list[str] = []          # parallel to _bucket_lists
        self._bucket_lists: list[list[int]] = []   # rule indices per bucket
        # litidx: case-folded needle -> rule-id postings, + the
        # always-verify rule-index set.  Empty => no prefilter.
        self._lit_needles: list[str] = []            # parallel to _lit_postings
        self._lit_postings: list[list[tuple]] = []   # (rule_idx, field_id, clause) per needle
        self._lit_always_verify: list[int] = []
        self._rule_clauses: list[int] = []           # witness clauses per rule index
        self._fwits: list[tuple] = []                # (rule_idx, field_id, clause, op, ival)

    # -- interning -----------------------------------------------------------
    def _intern(self, s: str) -> tuple[int, int]:
        b = s.encode("utf-8")
        off = len(self._pool)
        self._pool += b
        return off, len(b)

    def _intern_cstr(self, s: str) -> tuple[int, int]:
        """Intern `s` with a trailing NUL; the returned len EXCLUDES it.

        Used for field names so the strpool slice is a valid C string at
        match time (zero-copy field callback), see field()."""
        b = s.encode("utf-8")
        off = len(self._pool)
        self._pool += b
        self._pool += b"\x00"
        return off, len(b)

    def field_id(self, name: str) -> "int | None":
        """The id of an ALREADY-interned field, or None if the name was never
        used by a predicate (so nothing can be scoped to it)."""
        return self._field_ids.get(name)

    def field(self, name: str) -> int:
        fid = self._field_ids.get(name)
        if fid is not None:
            return fid
        # .sigmac contract: field-NAME strpool entries are NUL-terminated.
        # A zero-copy field-resolve callback passes `strpool + off` straight to
        # a C-string API with NO bounce-buffer/memcpy, so the byte at
        # strpool[off + len] MUST be '\0'.
        # `len` excludes the terminator (so all length-prefixed comparisons are
        # unchanged); the trailing NUL costs one byte per distinct field name.
        # Values/titles/mitre/bucket-key strings are length-only and unaffected.
        off, ln = self._intern_cstr(name)
        fid = len(self.fields)
        self.fields.append((off, ln))
        self._field_ids[name] = fid
        return fid

    def value(self, s: str) -> int:
        off, ln = self._intern(s)
        vid = len(self.values)
        self.values.append((off, ln))
        return vid

    def cidr(self, family: int, prefix: int, net: bytes) -> int:
        padded = net[:16].ljust(16, b"\x00")
        for i, (fam, pfx, existing) in enumerate(self.cidrs):
            if fam == family and pfx == prefix and existing == padded:
                return i
        cid = len(self.cidrs)
        self.cidrs.append((family, prefix, padded))
        return cid

    # -- rule construction ---------------------------------------------------
    def pred(self, field_name: str, op: int, *, value_id: int = NO_VALUE,
             group: int = 0, flags: int = 0, ival: int = 0) -> None:
        self.preds.append(_Pred(self.field(field_name), group, int(op), flags,
                                value_id, ival))

    def begin_sel(self) -> int:
        return len(self.preds)

    def end_sel(self, pred_start: int) -> int:
        sid = len(self.sels)
        self.sels.append((pred_start, len(self.preds) - pred_start))
        return sid

    def rule(self, rule_id: int, sel_start: int, sel_count: int, *,
             cond: list[tuple[int, int]] | None = None,
             verdict: int = Verdict.ALERT, severity: int = 1,
             score_x100: int = 0, name_id: int = NO_VALUE,
             mitre_id: int = NO_VALUE) -> int:
        cond = cond or []
        cond_start = len(self.cond)
        self.cond.extend(cond)
        self.rules.append(_Rule(rule_id, sel_start, sel_count, cond_start,
                                len(cond), int(verdict), severity, score_x100,
                                name_id, mitre_id))
        return len(self.rules) - 1

    # -- bucket index ---------------------------------------------
    def set_buckets(self, buckets: "dict[str, list[int]]") -> None:
        """Install the logsource/category bucket index.

        `buckets` maps a bucket KEY (an ECS event.category token, or a
        Sigma product/service token such as linux/cisco/sshd; "" =
        the always-verify bucket) to a list of rule INDICES into self.rules.
        The matcher reads the key from event.category then the product-name
        fields (product / techno / technology) then the older ECS aliases, and
        unions every bucket they hit. Empty/zero-rule
        buckets are dropped; ordering is stable for deterministic output.
        Calling with an empty mapping (or never calling) emits a no-bucket-index
        artifact (no index -> linear-scan fallback in C).
        """
        self._bucket_keys = []
        self._bucket_lists = []
        for key in sorted(buckets):
            ids = buckets[key]
            if not ids:
                continue
            self._bucket_keys.append(key)
            self._bucket_lists.append(list(ids))

    # -- literal prefilter index -------------------------------
    def set_litidx(self, needle_refs: "dict[str, list[tuple]]",
                   always_verify: "list[int]",
                   rule_clauses: "list[int] | None" = None,
                   fwits: "list[tuple] | None" = None) -> None:
        """Install the SIMD literal-prefilter index.

        `needle_refs` maps a case-folded needle to its postings: a list of
        ``(rule_idx, field_id, clause_idx)`` triples meaning "this needle,
        occurring in field `field_id` (or ANY_FIELD), satisfies witness clause
        `clause_idx` of rule `rule_idx`".  `fwits` are the numeric/CIDR atoms of
        the same CNF: ``(rule_idx, field_id, clause_idx, op, ival)``.
        `rule_clauses` gives each rule index its clause count, so the matcher
        knows when a rule's witness set is complete; `always_verify` lists the
        rules with no sound required atom at all, which are NEVER prefiltered
        out and must have a clause count of zero.  Needles are emitted in
        sorted order for deterministic output; empty needles / empty postings
        are dropped.  Calling with an empty mapping and no fwits (or never
        calling) emits no litidx (the C matcher then runs the bucket scan with
        no prefilter).
        """
        self._lit_needles = []
        self._lit_postings = []
        for needle in sorted(needle_refs):
            refs = needle_refs[needle]
            if not needle or not refs:
                continue
            self._lit_needles.append(needle)
            self._lit_postings.append(list(refs))
        self._lit_always_verify = list(always_verify)
        self._rule_clauses = list(rule_clauses) if rule_clauses else []
        self._fwits = list(fwits) if fwits else []

    # -- serialization -------------------------------------------------------
    def serialize(self, *, version: int = VERSION) -> bytes:
        """Serialize to a `.sigmac` artifact.

        The bucket index is included when one has been installed (set_buckets),
        and the litidx literal-prefilter index when literals have been installed;
        otherwise their counts are 0 and the C matcher falls back accordingly
        (full linear scan / no prefilter).  Output is byte-stable across calls
        (no mutation of builder state).
        """
        if version != VERSION:
            raise ValueError(
                f"unsupported .sigmac version {version}: only version {VERSION} is emitted"
            )
        emit_buckets = bool(self._bucket_keys)
        emit_litidx = (bool(self._lit_needles) or bool(self._lit_always_verify)
                       or bool(self._fwits))
        hdr_size = HDR_SIZE

        # Bucket keys AND litidx needles are interned into a LOCAL copy of the
        # strpool so serialize stays side-effect-free (idempotent determinism).
        pool = bytearray(self._pool)
        bkey_refs: list[tuple[int, int]] = []      # (off, len) per bucket key
        flat_idx: list[int] = []                    # flat rule-index pool
        bucket_descr: list[tuple[int, int]] = []    # (idx_start, idx_count)
        if emit_buckets:
            for key, ids in zip(self._bucket_keys, self._bucket_lists):
                kb = key.encode("utf-8")
                off = len(pool)
                pool += kb
                bkey_refs.append((off, len(kb)))
                start = len(flat_idx)
                flat_idx.extend(ids)
                bucket_descr.append((start, len(ids)))

        n_buckets = len(bkey_refs)
        n_bidx = len(flat_idx)

        # litidx: needle strings + per-needle postings + the flat
        # postings pool + the always-verify rule-index list.
        lit_ndl_refs: list[tuple[int, int]] = []    # (off, len) per needle
        lit_post_descr: list[tuple[int, int]] = []  # (idx_start, idx_count)
        lit_post_ref: list[tuple] = []              # flat (rule, field, clause) pool
        if emit_litidx:
            for needle, refs in zip(self._lit_needles, self._lit_postings):
                nb = needle.encode("utf-8")
                off = len(pool)
                pool += nb
                lit_ndl_refs.append((off, len(nb)))
                start = len(lit_post_ref)
                lit_post_ref.extend(refs)
                lit_post_descr.append((start, len(refs)))
        n_litndl = len(lit_ndl_refs)
        n_litpost_ref = len(lit_post_ref)
        n_litav = len(self._lit_always_verify) if emit_litidx else 0
        rule_clauses = self._rule_clauses if emit_litidx else []
        if rule_clauses and len(rule_clauses) != len(self.rules):
            raise ValueError(
                f"rule_clauses has {len(rule_clauses)} entries for {len(self.rules)} rules"
            )
        n_rule_clauses = len(rule_clauses)

        off_fields = _align8(hdr_size)
        off_values = _align8(off_fields + len(self.fields) * SZ_STR)
        off_preds = _align8(off_values + len(self.values) * SZ_STR)
        off_sels = _align8(off_preds + len(self.preds) * SZ_PRED)
        off_cond = _align8(off_sels + len(self.sels) * SZ_SEL)
        off_rules = _align8(off_cond + len(self.cond) * SZ_CTOK)
        off_cidrs = _align8(off_rules + len(self.rules) * SZ_RULE)
        off_bkeys = _align8(off_cidrs + len(self.cidrs) * SZ_CIDR)
        off_buckets = _align8(off_bkeys + n_buckets * SZ_STR)
        off_bidx = _align8(off_buckets + n_buckets * SZ_BUCKET)
        off_litndl = _align8(off_bidx + n_bidx * 4)
        off_litpost = _align8(off_litndl + n_litndl * SZ_STR)
        off_litpost_ref = _align8(off_litpost + n_litndl * SZ_LITPOST)
        off_litav = _align8(off_litpost_ref + n_litpost_ref * SZ_LITREF)
        off_rule_clauses = _align8(off_litav + n_litav * 4)
        n_fwit = len(self._fwits) if emit_litidx else 0
        off_fwit = _align8(off_rule_clauses + n_rule_clauses)
        off_strpool = _align8(off_fwit + n_fwit * SZ_FWIT)
        total = off_strpool + len(pool) + 4  # + CRC32C

        buf = bytearray(total)
        struct.pack_into(
            "<2IQ32I", buf, 0,
            MAGIC, VERSION, total,
            len(self.fields), off_fields,
            len(self.values), off_values,
            len(self.preds), off_preds,
            len(self.sels), off_sels,
            len(self.cond), off_cond,
            len(self.rules), off_rules,
            len(pool), off_strpool,
            len(self.cidrs), off_cidrs,
            0,  # flags
            n_buckets, (off_bkeys if n_buckets else 0),
            (off_buckets if n_buckets else 0),
            n_bidx, (off_bidx if n_bidx else 0),
            # litidx
            n_litndl, (off_litndl if n_litndl else 0),
            (off_litpost if n_litndl else 0),
            n_litpost_ref, (off_litpost_ref if n_litpost_ref else 0),
            n_litav, (off_litav if n_litav else 0),
            (off_rule_clauses if n_rule_clauses else 0),
            n_fwit, (off_fwit if n_fwit else 0),
        )
        for i, (o, ln) in enumerate(self.fields):
            struct.pack_into("<2I", buf, off_fields + i * SZ_STR, o, ln)
        for i, (o, ln) in enumerate(self.values):
            struct.pack_into("<2I", buf, off_values + i * SZ_STR, o, ln)
        for i, p in enumerate(self.preds):
            struct.pack_into("<HHBB2xI4xq", buf, off_preds + i * SZ_PRED,
                             p.field_id, p.group_id, p.op, p.flags, p.value_id, p.ival)
        for i, (ps, pc) in enumerate(self.sels):
            struct.pack_into("<2I", buf, off_sels + i * SZ_SEL, ps, pc)
        for i, (kind, sidx) in enumerate(self.cond):
            struct.pack_into("<B3xI", buf, off_cond + i * SZ_CTOK, kind, sidx)
        for i, r in enumerate(self.rules):
            struct.pack_into("<5IBBH2I", buf, off_rules + i * SZ_RULE,
                             r.rule_id, r.sel_start, r.sel_count, r.cond_start,
                             r.cond_count, r.verdict, r.severity, r.score_x100,
                             r.name_id, r.mitre_id)
        for i, (fam, pfx, net) in enumerate(self.cidrs):
            struct.pack_into("<BB2x16s", buf, off_cidrs + i * SZ_CIDR, fam, pfx, net)
        if emit_buckets:
            for i, (o, ln) in enumerate(bkey_refs):
                struct.pack_into("<2I", buf, off_bkeys + i * SZ_STR, o, ln)
            for i, (st, cnt) in enumerate(bucket_descr):
                struct.pack_into("<2I", buf, off_buckets + i * SZ_BUCKET, st, cnt)
            for i, ridx in enumerate(flat_idx):
                struct.pack_into("<I", buf, off_bidx + i * 4, ridx)
        if emit_litidx:
            for i, (o, ln) in enumerate(lit_ndl_refs):
                struct.pack_into("<2I", buf, off_litndl + i * SZ_STR, o, ln)
            for i, (st, cnt) in enumerate(lit_post_descr):
                struct.pack_into("<2I", buf, off_litpost + i * SZ_LITPOST, st, cnt)
            for i, (ridx, fid, clause) in enumerate(lit_post_ref):
                struct.pack_into("<IHBB", buf, off_litpost_ref + i * SZ_LITREF, ridx, fid, clause, 0)
            for i, ridx in enumerate(self._lit_always_verify):
                struct.pack_into("<I", buf, off_litav + i * 4, ridx)
            for i, n in enumerate(rule_clauses):
                struct.pack_into("<B", buf, off_rule_clauses + i, n)
            for i, (ridx, fid, clause, op, ival) in enumerate(self._fwits):
                struct.pack_into("<IHBBq", buf, off_fwit + i * SZ_FWIT,
                                 ridx, fid, clause, op, ival)
        buf[off_strpool:off_strpool + len(pool)] = pool

        crc = crc32c(bytes(buf[:total - 4]))
        struct.pack_into("<I", buf, total - 4, crc)
        return bytes(buf)
