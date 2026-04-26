"""End-to-end behavioral tests for the Names dedup engine.

Each scenario builds a small corpus of `NamesRecordDict`-shaped
records, simulates what the OpenSearch dedup aggregation would
return for that corpus, calls the public
`NamesSyncService.find_duplicate_candidates(...)` method, and
compares the *complete* returned list against an explicit expected
list. Tests deliberately do not poke at internal helpers
(`_score_bucket_pairs`, `_record_*`, etc.) so a reorganization of
the scoring pipeline can land without test churn.

The vendored ~70k-row given-name equivalence index is replaced with
a small in-memory stub via an autouse fixture, so each scenario
runs without paying the ~1 s / ~230 MB CSV load cost incurred by
`PersonNameComparator` on first use.
"""

from __future__ import annotations

from typing import Any

import pytest

from invenio_remote_user_data_kcworks.services import name_similarity
from invenio_remote_user_data_kcworks.services.names_sync import (
    NamesSyncService,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def stub_equivalence_index(monkeypatch):
    """Replace the vendored equivalence index with a small in-memory stub.

    Keeps `PersonNameComparator._compatible()` from ever loading the
    real ~70k-row CSV. The stub maps `alex`/`alexander` to a shared
    canonical root so the equivalence-index branch is reachable in
    Scenario A; every other given-name pair in these tests is either
    exact-equal (compares trivially) or fully disjoint (relies on the
    fuzzy fallback's natural failure).
    """
    stub: dict[str, frozenset[str]] = {
        "alex":      frozenset({"alex/alexander"}),
        "alexander": frozenset({"alex/alexander"}),
    }
    monkeypatch.setattr(
        name_similarity, "_DEFAULT_EQUIVALENCE_INDEX", stub
    )


@pytest.fixture()
def service(base_app) -> NamesSyncService:
    """Construct a `NamesSyncService` against the pytest-invenio base app.

    `__init__` only reads `app.config` and `app.logger`; no
    service-registry lookup happens until the `names_service`
    property is touched. These end-to-end tests never touch it
    (`_fetch_dedup_buckets`, the only OS-using method, is patched
    per-test), so no OpenSearch / DB connectivity is needed.

    Returns:
        A freshly constructed `NamesSyncService` bound to the
        pytest-invenio `base_app`.
    """
    return NamesSyncService(base_app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(
    *,
    uuid: str,
    given_name: str = "",
    family_name: str = "",
    family_token: str = "",
    family_part_tokens: list[str] | None = None,
    family_phonetic_tokens: list[str] | None = None,
    orcid: str | None = None,
    dismissed_duplicates: list[str] | None = None,
) -> dict[str, Any]:
    """Build a `NamesRecordDict`-shaped literal for scoring tests.

    `family_part_tokens` defaults to `[family_token]` when only the
    singular form is supplied, matching what the production payload
    builder would emit for a single-piece family name. Pass an
    explicit `family_part_tokens=[...]` to model multi-piece names
    such as "García López" where the full canonical form is element
    0 and the constituent pieces follow.

    Returns:
        A `NamesRecordDict`-shaped `dict` ready to feed into
        `make_buckets_payload` (or directly into a mocked
        `_fetch_dedup_buckets` payload).
    """
    if family_part_tokens is None and family_token:
        family_part_tokens = [family_token]
    props: dict[str, Any] = {}
    if family_token:
        props["family_token"] = family_token
    if family_part_tokens:
        props["family_part_tokens"] = list(family_part_tokens)
    if family_phonetic_tokens:
        props["family_phonetic_tokens"] = list(family_phonetic_tokens)
    if dismissed_duplicates:
        props["dismissed_duplicates"] = list(dismissed_duplicates)
    identifiers: list[dict[str, str]] = []
    if orcid:
        identifiers.append({"scheme": "orcid", "identifier": orcid})
    return {
        "uuid": uuid,
        "id": f"kc|{uuid[:8]}",
        "given_name": given_name,
        "family_name": family_name,
        "props": props,
        "identifiers": identifiers,
    }


def make_buckets_payload(
    records: list[dict[str, Any]],
) -> dict[str, list[tuple[str, list[dict[str, Any]]]]]:
    """Simulate the OpenSearch dedup aggregation over the given records.

    For each record, drop a reference into every token bucket keyed
    by an entry in `props.family_part_tokens`, and into every
    phonetic bucket keyed by an entry in
    `props.family_phonetic_tokens`. Singleton buckets (mirroring
    `min_doc_count=2` in the production aggregation) are dropped.

    Bucket order in each pass follows insertion order — i.e., a
    bucket appears at the position where its key was first seen
    while walking `records`. Member order within a bucket follows
    the order each record appears in `records`. Both orderings let
    test authors reason deterministically about which record will
    end up as `record_a` vs `record_b` in the final candidate list,
    and which equally-scored pair will appear first after the stable
    descending sort.

    Returns:
        The `{"token": [...], "phonetic": [...]}` payload shape that
        the production `_fetch_dedup_buckets` would have produced
        for this corpus.
    """
    token_buckets: dict[str, list[dict[str, Any]]] = {}
    phonetic_buckets: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        props = rec.get("props", {})
        for token in props.get("family_part_tokens", []) or []:
            token_buckets.setdefault(token, []).append(rec)
        for code in props.get("family_phonetic_tokens", []) or []:
            phonetic_buckets.setdefault(code, []).append(rec)
    return {
        "token":    [(k, v) for k, v in token_buckets.items() if len(v) >= 2],
        "phonetic": [(k, v) for k, v in phonetic_buckets.items() if len(v) >= 2],
    }


def _patch_buckets(monkeypatch, service, payload):
    """Replace `_fetch_dedup_buckets` with a fixed-payload stub."""
    monkeypatch.setattr(
        service, "_fetch_dedup_buckets",
        lambda *, identity, limit: payload,
    )


# ---------------------------------------------------------------------------
# Scenario A — Mixed corpus, single sweep
# ---------------------------------------------------------------------------


def test_mixed_corpus_yields_full_expected_candidate_list(
    service, monkeypatch
):
    """A diverse corpus surfaces exactly the documented set of pairs.

    The corpus models eight role-tagged record pairs; the call must
    return exactly the six `INCLUDED_*` pairs (the two `EXCLUDED_*`
    pairs are dropped by either threshold or dismissed-duplicate
    logic). The full output list is asserted dict-equal so any drift
    in score, score_method, family_token, shared_orcid flag, ORDER,
    or the embedded record dicts surfaces immediately.
    """
    orcid_value = "0000-0001-2345-6789"

    # --- Pair 1 (INCLUDED): identical full-family duplicate ----------------
    smith_1 = _make_record(
        uuid="smith-1", given_name="John", family_name="Smith",
        family_token="smith", family_phonetic_tokens=["SM0"],
    )
    smith_2 = _make_record(
        uuid="smith-2", given_name="John", family_name="Smith",
        family_token="smith", family_phonetic_tokens=["SM0"],
    )

    # --- Pair 2 (INCLUDED): hyphenated family, partial-piece overlap -------
    garcia_lopez = _make_record(
        uuid="garcia-lopez", given_name="John",
        family_name="García López",
        family_token="garcia lopez",
        family_part_tokens=["garcia lopez", "garcia", "lopez"],
        family_phonetic_tokens=["KRS", "LPS"],
    )
    garcia = _make_record(
        uuid="garcia", given_name="John", family_name="García",
        family_token="garcia",
        family_phonetic_tokens=["KRS"],
    )

    # --- Pair 3 (INCLUDED): phonetic-only spelling variant ----------------
    obrien = _make_record(
        uuid="obrien", given_name="Joel", family_name="O'Brien",
        family_token="obrien",
        family_phonetic_tokens=["OBRN"],
    )
    obrian = _make_record(
        uuid="obrian", given_name="Joel", family_name="O'Brian",
        family_token="obrian",
        family_phonetic_tokens=["OBRN"],
    )

    # --- Pair 4 (INCLUDED): nickname equivalence (Alex / Alexander) -------
    carter_alex = _make_record(
        uuid="carter-alex", given_name="Alex", family_name="Carter",
        family_token="carter",
        family_phonetic_tokens=["KRTR"],
    )
    carter_alexander = _make_record(
        uuid="carter-alexander", given_name="Alexander",
        family_name="Carter",
        family_token="carter",
        family_phonetic_tokens=["KRTR"],
    )

    # --- Pair 5 (INCLUDED): cited stubs, no given_name --------------------
    okafor_stub_1 = _make_record(
        uuid="okafor-stub-1", given_name="", family_name="Okafor",
        family_token="okafor",
        family_phonetic_tokens=["OKFR"],
    )
    okafor_stub_2 = _make_record(
        uuid="okafor-stub-2", given_name="", family_name="Okafor",
        family_token="okafor",
        family_phonetic_tokens=["OKFR"],
    )

    # --- Pair 6 (INCLUDED): two records sharing an ORCID ------------------
    patel_1 = _make_record(
        uuid="patel-1", given_name="Anita", family_name="Patel",
        family_token="patel",
        family_phonetic_tokens=["PTL"],
        orcid=orcid_value,
    )
    patel_2 = _make_record(
        uuid="patel-2", given_name="Anita", family_name="Patel",
        family_token="patel",
        family_phonetic_tokens=["PTL"],
        orcid=orcid_value,
    )

    # --- Pair 7 (EXCLUDED): same family, disjoint given names -------------
    webb_john = _make_record(
        uuid="webb-john", given_name="John", family_name="Webb",
        family_token="webb",
        family_phonetic_tokens=["WB"],
    )
    webb_mary = _make_record(
        uuid="webb-mary", given_name="Mary", family_name="Webb",
        family_token="webb",
        family_phonetic_tokens=["WB"],
    )

    # --- Pair 8 (EXCLUDED): pair previously dismissed by reviewer --------
    chen_1 = _make_record(
        uuid="chen-1", given_name="Wei", family_name="Chen",
        family_token="chen",
        family_phonetic_tokens=["XN"],
        dismissed_duplicates=["chen-2"],
    )
    chen_2 = _make_record(
        uuid="chen-2", given_name="Wei", family_name="Chen",
        family_token="chen",
        family_phonetic_tokens=["XN"],
    )

    corpus = [
        smith_1, smith_2,
        garcia_lopez, garcia,
        obrien, obrian,
        carter_alex, carter_alexander,
        okafor_stub_1, okafor_stub_2,
        patel_1, patel_2,
        webb_john, webb_mary,
        chen_1, chen_2,
    ]
    _patch_buckets(monkeypatch, service, make_buckets_payload(corpus))

    expected = [
        # score 1.0 — full family + identical given (insertion order on tie):
        {
            "score": 1.0,
            "score_method": "family_exact+given_fuzzy",
            "family_token": "smith",
            "shared_orcid": False,
            "record_a": smith_1,
            "record_b": smith_2,
        },
        {
            "score": 1.0,
            "score_method": "family_exact+given_fuzzy",
            "family_token": "carter",
            "shared_orcid": False,
            "record_a": carter_alex,
            "record_b": carter_alexander,
        },
        {
            "score": 1.0,
            "score_method": "family_exact+given_fuzzy",
            "family_token": "patel",
            "shared_orcid": True,
            "record_a": patel_1,
            "record_b": patel_2,
        },
        # score 0.9 — partial-family discount on the "garcia" piece bucket
        # (full forms differ: "garcia lopez" vs "garcia"):
        {
            "score": 0.9,
            "score_method": "family_partial+given_fuzzy",
            "family_token": "garcia lopez",
            "shared_orcid": False,
            "record_a": garcia_lopez,
            "record_b": garcia,
        },
        # score 0.85 — given_absent stubs, full family, then phonetic-only:
        {
            "score": 0.85,
            "score_method": "family_exact+given_absent",
            "family_token": "okafor",
            "shared_orcid": False,
            "record_a": okafor_stub_1,
            "record_b": okafor_stub_2,
        },
        {
            "score": 0.85,
            "score_method": "family_phonetic+given_fuzzy",
            "family_token": "obrien",
            "shared_orcid": False,
            "record_a": obrien,
            "record_b": obrian,
        },
    ]
    assert service.find_duplicate_candidates(limit=100) == expected


# ---------------------------------------------------------------------------
# Scenario B — No-dupes corpus
# ---------------------------------------------------------------------------


def test_no_duplicates_corpus_returns_empty_list(service, monkeypatch):
    """Singletons and sub-threshold pairs together yield no candidates.

    Mixes two failure modes the service must handle gracefully in
    one call:

    * Three records with disjoint family tokens — every token-pass
      and phonetic-pass bucket is a singleton and dropped before
      scoring even runs.
    * Two records sharing a family ("Yamada") but with totally
      disjoint given names ("Hiro" vs "Aiko") — bucket exists, the
      comparator runs, but the post-discount score sits below
      `GIVEN_NAME_SIMILARITY_THRESHOLD` so the pair is dropped.
    """
    corpus = [
        _make_record(
            uuid="solo-1", given_name="Aamir", family_name="Khan",
            family_token="khan", family_phonetic_tokens=["KN"],
        ),
        _make_record(
            uuid="solo-2", given_name="Beatriz", family_name="Sousa",
            family_token="sousa", family_phonetic_tokens=["SS"],
        ),
        _make_record(
            uuid="solo-3", given_name="Cyrus", family_name="Vance",
            family_token="vance", family_phonetic_tokens=["FNS"],
        ),
        _make_record(
            uuid="yamada-1", given_name="Hiro", family_name="Yamada",
            family_token="yamada", family_phonetic_tokens=["YMT"],
        ),
        _make_record(
            uuid="yamada-2", given_name="Aiko", family_name="Yamada",
            family_token="yamada", family_phonetic_tokens=["YMT"],
        ),
    ]
    _patch_buckets(monkeypatch, service, make_buckets_payload(corpus))

    assert service.find_duplicate_candidates(limit=100) == []


# ---------------------------------------------------------------------------
# Scenario C — Same pair surfaces in many buckets, kept once at best score
# ---------------------------------------------------------------------------


def test_pair_surfacing_in_many_buckets_is_kept_once_at_best_score(
    service, monkeypatch
):
    """A `García López` duplicate hits five buckets but is returned once.

    Both records are full-family `García López` with identical given
    names, so they collide in:

    * three token buckets — `"garcia lopez"`, `"garcia"`, `"lopez"`
    * two phonetic buckets — `"KRS"`, `"LPS"`

    Of those, only the `"garcia lopez"` bucket key matches the full
    canonical form on both sides, so it scores 1.0; the other four
    score 0.9 (partial-family discount) or 0.85 (phonetic discount).
    The dedup-by-pair step must keep exactly one entry, and it must
    be the 1.0 one.
    """
    rec_a = _make_record(
        uuid="gl-a", given_name="John", family_name="García López",
        family_token="garcia lopez",
        family_part_tokens=["garcia lopez", "garcia", "lopez"],
        family_phonetic_tokens=["KRS", "LPS"],
    )
    rec_b = _make_record(
        uuid="gl-b", given_name="John", family_name="García López",
        family_token="garcia lopez",
        family_part_tokens=["garcia lopez", "garcia", "lopez"],
        family_phonetic_tokens=["KRS", "LPS"],
    )
    _patch_buckets(monkeypatch, service, make_buckets_payload([rec_a, rec_b]))

    assert service.find_duplicate_candidates(limit=100) == [
        {
            "score": 1.0,
            "score_method": "family_exact+given_fuzzy",
            "family_token": "garcia lopez",
            "shared_orcid": False,
            "record_a": rec_a,
            "record_b": rec_b,
        },
    ]
