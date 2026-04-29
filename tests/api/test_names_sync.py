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

from datetime import UTC, datetime, timedelta
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
def service(base_app, monkeypatch) -> NamesSyncService:
    """Construct a `NamesSyncService` against the pytest-invenio base app.

    `__init__` only reads `app.config` and `app.logger`; no
    service-registry lookup happens until the `names_service`
    property is touched. These end-to-end tests never touch it
    (`_fetch_dedup_buckets`, the only OS-using method, is patched
    per-test), so no OpenSearch / DB connectivity is needed.

    Side-effect writes are stubbed out so each test can assert the
    pure shape of `find_duplicate_candidates`'s return value:

    * `_set_duplicates_for_pair` -> no-op returning `True`. The real
      implementation calls `names_service.update`, which would require
      a live records resources binding the corpus tests deliberately
      do not stand up.
    * `_read_dedup_bookmark` -> returns `None`. Keeps each test's
      `find_duplicate_candidates(...)` deterministic regardless of
      whatever any earlier test happened to write to the cache.
    * `_write_dedup_bookmark` -> no-op. Same reasoning, in reverse:
      no test should leave a bookmark behind for the next one.

    Tests that exercise the bookmark plumbing override these stubs
    locally (see the bookmark scenarios further down).

    Returns:
        A freshly constructed `NamesSyncService` bound to the
        pytest-invenio `base_app` with side-effect writes stubbed.
    """
    svc = NamesSyncService(base_app)
    monkeypatch.setattr(
        svc, "_set_duplicates_for_pair",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(svc, "_read_dedup_bookmark", lambda: None)
    monkeypatch.setattr(svc, "_write_dedup_bookmark", lambda ts: None)
    # The full-sweep GC needs `names_service.update`, which the
    # corpus tests deliberately don't stand up; stub to a stats-shaped
    # no-op so `full_sweep=True` paths in these scenarios stay pure.
    # The dedicated `_prune_stale_cross_refs` scenario re-stubs the
    # underlying I/O seams instead.
    monkeypatch.setattr(
        svc, "_prune_stale_cross_refs",
        lambda *, identity=None: {
            "inspected": 0, "pruned": 0, "keys_dropped": 0,
        },
    )
    return svc


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
    updated: str | None = None,
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
    rec: dict[str, Any] = {
        "uuid": uuid,
        "id": f"kc|{uuid[:8]}",
        "given_name": given_name,
        "family_name": family_name,
        "props": props,
        "identifiers": identifiers,
    }
    if updated is not None:
        rec["updated"] = updated
    return rec


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
        lambda *, identity, limit=None: payload,
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
    assert service.find_duplicate_candidates() == expected


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

    assert service.find_duplicate_candidates() == []


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

    assert service.find_duplicate_candidates() == [
        {
            "score": 1.0,
            "score_method": "family_exact+given_fuzzy",
            "family_token": "garcia lopez",
            "shared_orcid": False,
            "record_a": rec_a,
            "record_b": rec_b,
        },
    ]


# ---------------------------------------------------------------------------
# Scenario D — Incremental sweep: bookmark filters stale pairs
# ---------------------------------------------------------------------------


def _iso(ts: datetime) -> str:
    """Render `ts` as an ISO 8601 string of the form OS would index.

    Returns:
        UTC-normalized ISO 8601 representation of `ts`, matching the
        shape `_pair_touches_recent` will parse via `fromisoformat`.
    """
    return ts.astimezone(UTC).isoformat()


def test_since_drops_pairs_where_neither_side_has_been_touched(
    service, monkeypatch
):
    """A pair whose both sides predate the cutoff is dropped from the result.

    Models the steady-state incremental case: nothing in the corpus
    has changed since the last sweep, so even though the OS
    aggregation would still return the bucket, the candidate is
    skipped at pair-time.
    """
    bookmark = datetime(2026, 4, 20, 0, 0, tzinfo=UTC)
    stale_a = _make_record(
        uuid="stale-a", given_name="Mei", family_name="Lin",
        family_token="lin", family_phonetic_tokens=["LN"],
        updated=_iso(bookmark - timedelta(days=7)),
    )
    stale_b = _make_record(
        uuid="stale-b", given_name="Mei", family_name="Lin",
        family_token="lin", family_phonetic_tokens=["LN"],
        updated=_iso(bookmark - timedelta(days=2)),
    )
    _patch_buckets(monkeypatch, service, make_buckets_payload([stale_a, stale_b]))

    assert service.find_duplicate_candidates(since=bookmark) == []


def test_since_keeps_pair_when_one_side_was_touched_after_bookmark(
    service, monkeypatch
):
    """A pair with one fresh side (and one stale side) survives the filter.

    The whole point of pair-time filtering is to catch new joins
    where the freshly-touched record (e.g. a just-created cited stub)
    matches an older incumbent. Aggregation-time filtering on
    `updated` would miss this; pair-time filtering catches it.
    """
    bookmark = datetime(2026, 4, 20, 0, 0, tzinfo=UTC)
    incumbent = _make_record(
        uuid="incumbent", given_name="Mei", family_name="Lin",
        family_token="lin", family_phonetic_tokens=["LN"],
        updated=_iso(bookmark - timedelta(days=400)),
    )
    fresh = _make_record(
        uuid="fresh", given_name="Mei", family_name="Lin",
        family_token="lin", family_phonetic_tokens=["LN"],
        updated=_iso(bookmark + timedelta(hours=1)),
    )
    _patch_buckets(monkeypatch, service, make_buckets_payload([incumbent, fresh]))

    assert service.find_duplicate_candidates(since=bookmark) == [
        {
            "score": 1.0,
            "score_method": "family_exact+given_fuzzy",
            "family_token": "lin",
            "shared_orcid": False,
            "record_a": incumbent,
            "record_b": fresh,
        },
    ]


def test_full_sweep_ignores_bookmark_and_returns_stale_pair(
    service, monkeypatch
):
    """`full_sweep=True` overrides the cached bookmark *and* `since`.

    Mixes both override paths in one call: the fixture's
    `_read_dedup_bookmark` returns `None` already, but we also pass
    `since=` in the future to confirm `full_sweep` wins. A periodic
    full sweep is the only way to catch pairs whose `updated`
    timestamps drifted (e.g. due to an upstream reindex) without
    actually changing the duplicate-relevant fields.
    """
    bookmark = datetime(2026, 4, 20, 0, 0, tzinfo=UTC)
    stale_a = _make_record(
        uuid="stale-a", given_name="Mei", family_name="Lin",
        family_token="lin", family_phonetic_tokens=["LN"],
        updated=_iso(bookmark - timedelta(days=7)),
    )
    stale_b = _make_record(
        uuid="stale-b", given_name="Mei", family_name="Lin",
        family_token="lin", family_phonetic_tokens=["LN"],
        updated=_iso(bookmark - timedelta(days=2)),
    )
    _patch_buckets(monkeypatch, service, make_buckets_payload([stale_a, stale_b]))

    assert service.find_duplicate_candidates(
        since=bookmark, full_sweep=True
    ) == [
        {
            "score": 1.0,
            "score_method": "family_exact+given_fuzzy",
            "family_token": "lin",
            "shared_orcid": False,
            "record_a": stale_a,
            "record_b": stale_b,
        },
    ]


def test_missing_updated_timestamp_keeps_pair_in_scope(service, monkeypatch):
    """Records without an `updated` field always pass the bookmark filter.

    Older records pre-dating the field, or upstream paths that don't
    project `updated` into the indexed doc, must not be silently
    dropped from incremental sweeps. Defaulting "missing timestamp"
    to "include the pair" keeps recall conservative.
    """
    bookmark = datetime(2026, 4, 20, 0, 0, tzinfo=UTC)
    no_ts_a = _make_record(
        uuid="no-ts-a", given_name="Mei", family_name="Lin",
        family_token="lin", family_phonetic_tokens=["LN"],
    )
    no_ts_b = _make_record(
        uuid="no-ts-b", given_name="Mei", family_name="Lin",
        family_token="lin", family_phonetic_tokens=["LN"],
    )
    _patch_buckets(monkeypatch, service, make_buckets_payload([no_ts_a, no_ts_b]))

    assert service.find_duplicate_candidates(since=bookmark) == [
        {
            "score": 1.0,
            "score_method": "family_exact+given_fuzzy",
            "family_token": "lin",
            "shared_orcid": False,
            "record_a": no_ts_a,
            "record_b": no_ts_b,
        },
    ]


def test_default_run_consults_cached_bookmark_via_helper(
    service, monkeypatch
):
    """Without `since` or `full_sweep`, the helper-cached bookmark applies.

    Confirms the wiring path the production code actually uses: the
    cache layer is consulted via `_read_dedup_bookmark`, the result
    flows into the same pair-time filter, and a successful run
    rewrites the bookmark via `_write_dedup_bookmark`. The fixture
    stubs both helpers; this test re-stubs them locally to exercise
    the contract.
    """
    bookmark = datetime(2026, 4, 20, 0, 0, tzinfo=UTC)

    written: list[datetime] = []
    monkeypatch.setattr(service, "_read_dedup_bookmark", lambda: bookmark)
    monkeypatch.setattr(service, "_write_dedup_bookmark", written.append)

    stale_a = _make_record(
        uuid="stale-a", given_name="Mei", family_name="Lin",
        family_token="lin", family_phonetic_tokens=["LN"],
        updated=_iso(bookmark - timedelta(days=7)),
    )
    stale_b = _make_record(
        uuid="stale-b", given_name="Mei", family_name="Lin",
        family_token="lin", family_phonetic_tokens=["LN"],
        updated=_iso(bookmark - timedelta(days=2)),
    )
    _patch_buckets(monkeypatch, service, make_buckets_payload([stale_a, stale_b]))

    assert service.find_duplicate_candidates() == []
    # Bookmark is advanced once even when no candidates were emitted;
    # the next run is then anchored at this sweep's start time, not
    # the prior bookmark, so the corpus does not get re-evaluated
    # against an ever-older cutoff.
    assert len(written) == 1
    assert written[0] >= bookmark


# ---------------------------------------------------------------------------
# Scenario E — Stale-cross-reference GC (full-sweep only)
# ---------------------------------------------------------------------------


def test_prune_stale_cross_refs_drops_dead_uuids_and_preserves_live(
    base_app, monkeypatch
):
    """`_prune_stale_cross_refs` rewrites only records that need it.

    Three records carry `possible_duplicates` maps:

    * `mixed` — one live ref + one dead ref. Should be rewritten with
      only the live entry surviving.
    * `only-stale` — sole entry points to a deleted UUID. Should be
      rewritten with the entry dropped (resulting empty dict is left
      in place; reaping empty dicts is the indexer's problem, not
      ours).
    * `only-live` — sole entry points to a live UUID. Should be left
      alone — no gratuitous write.

    The test stubs the two I/O seams (`_fetch_live_uuids`,
    `_fetch_records_with_cross_refs`) and replaces the `names_service`
    descriptor with a stand-in whose `update` records the writes,
    rather than standing up a live records-resources binding.
    """
    svc = NamesSyncService(base_app)

    mixed: dict[str, Any] = {
        "uuid": "alive-1",
        "id": "kc|alive1",
        "props": {
            "possible_duplicates": {
                "alive-2": [1.0, "family_exact+given_fuzzy"],
                "ghost-x": [0.9, "family_partial+given_fuzzy"],
            },
        },
    }
    only_stale: dict[str, Any] = {
        "uuid": "alive-3",
        "id": "kc|alive3",
        "props": {
            "possible_duplicates": {
                "ghost-y": [0.85, "family_phonetic+given_fuzzy"],
            },
        },
    }
    only_live: dict[str, Any] = {
        "uuid": "alive-4",
        "id": "kc|alive4",
        "props": {
            "possible_duplicates": {
                "alive-2": [1.0, "family_exact+given_fuzzy"],
            },
        },
    }

    monkeypatch.setattr(
        svc, "_fetch_live_uuids",
        lambda *, identity: {"alive-1", "alive-2", "alive-3", "alive-4"},
    )
    monkeypatch.setattr(
        svc, "_fetch_records_with_cross_refs",
        lambda *, identity: [mixed, only_stale, only_live],
    )

    # Replace the `names_service` property at class level for this
    # test so `service.update(...)` lands in a capture list. The
    # stand-in only needs the one method `_prune_stale_cross_refs`
    # actually calls.
    captured: list[tuple[str, dict[str, Any]]] = []

    class _FakeNamesService:
        def update(self, identity, pid, rec):
            captured.append((pid, rec))

    monkeypatch.setattr(
        NamesSyncService, "names_service", _FakeNamesService()
    )

    stats = svc._prune_stale_cross_refs()

    assert stats == {"inspected": 3, "pruned": 2, "keys_dropped": 2}
    assert [pid for pid, _ in captured] == ["kc|alive1", "kc|alive3"]
    assert captured[0][1]["props"]["possible_duplicates"] == {
        "alive-2": [1.0, "family_exact+given_fuzzy"],
    }
    assert captured[1][1]["props"]["possible_duplicates"] == {}
    # only_live was untouched — no third write.
    assert len(captured) == 2


def test_prune_stale_cross_refs_bails_on_empty_live_set(
    base_app, monkeypatch
):
    """An empty live-set short-circuits without writing anything.

    Defensive guard: if the live-UUID query returned `set()` (e.g.
    because the search backend errored and the helper logged + bailed),
    treating every cross-ref as stale would clear the entire
    `possible_duplicates` graph in one sweep. The guard makes that
    impossible.
    """
    svc = NamesSyncService(base_app)

    rec: dict[str, Any] = {
        "uuid": "alive-1",
        "id": "kc|alive1",
        "props": {
            "possible_duplicates": {
                "alive-2": [1.0, "family_exact+given_fuzzy"],
            },
        },
    }

    monkeypatch.setattr(svc, "_fetch_live_uuids", lambda *, identity: set())
    # Should never even be called given the early return; assert so
    # by raising if it is.

    def _should_not_be_called(*args, **kwargs):
        raise AssertionError(
            "_fetch_records_with_cross_refs called despite empty live set"
        )

    monkeypatch.setattr(
        svc, "_fetch_records_with_cross_refs", _should_not_be_called
    )

    captured: list[tuple[str, dict[str, Any]]] = []

    class _FakeNamesService:
        def update(self, identity, pid, rec):
            captured.append((pid, rec))

    monkeypatch.setattr(
        NamesSyncService, "names_service", _FakeNamesService()
    )

    stats = svc._prune_stale_cross_refs()

    assert stats == {"inspected": 0, "pruned": 0, "keys_dropped": 0}
    assert captured == []
    # Original record is untouched — if a future change starts
    # mutating in place before the live-set check, this catches it.
    assert rec["props"]["possible_duplicates"] == {
        "alive-2": [1.0, "family_exact+given_fuzzy"],
    }


# ---------------------------------------------------------------------------
# Scenario F — list_duplicate_pairs (read-only view of marked duplicates)
# ---------------------------------------------------------------------------


def test_list_duplicate_pairs_emits_one_row_per_symmetric_edge(
    base_app, monkeypatch
):
    """Two distinct edges produce two rows, sorted by score descending.

    Stubs `_fetch_records_with_cross_refs` with four records forming
    two symmetric edges:

    * `(alive-1, alive-2)` at score 0.95 — the higher pair.
    * `(alive-3, alive-4)` at score 0.80.

    Each side carries the reverse cross-reference, so no warnings
    fire and both edges land in the output. The result is sorted by
    score descending and dedup'd to one row per edge (the four
    records produce two rows, not four).
    """
    svc = NamesSyncService(base_app)

    rec_1 = {
        "uuid": "alive-1", "id": "kc|alive1", "name": "Doe, John",
        "props": {"possible_duplicates": {
            "alive-2": [0.95, "family_exact+given_fuzzy"],
        }},
    }
    rec_2 = {
        "uuid": "alive-2", "id": "kc|alive2", "name": "Doe, Jonathan",
        "props": {"possible_duplicates": {
            "alive-1": [0.95, "family_exact+given_fuzzy"],
        }},
    }
    rec_3 = {
        "uuid": "alive-3", "id": "kc|alive3", "name": "Lin, Mei",
        "props": {"possible_duplicates": {
            "alive-4": [0.80, "family_phonetic+given_fuzzy"],
        }},
    }
    rec_4 = {
        "uuid": "alive-4", "id": "kc|alive4", "name": "Lin, May",
        "props": {"possible_duplicates": {
            "alive-3": [0.80, "family_phonetic+given_fuzzy"],
        }},
    }

    monkeypatch.setattr(
        svc, "_fetch_records_with_cross_refs",
        lambda *, identity: [rec_1, rec_2, rec_3, rec_4],
    )

    rows = svc.list_duplicate_pairs()

    assert rows == [
        {
            "score": 0.95,
            "score_method": "family_exact+given_fuzzy",
            "a_uuid": "alive-1", "a_pid": "kc|alive1", "a_name": "Doe, John",
            "b_uuid": "alive-2", "b_pid": "kc|alive2", "b_name": "Doe, Jonathan",
        },
        {
            "score": 0.80,
            "score_method": "family_phonetic+given_fuzzy",
            "a_uuid": "alive-3", "a_pid": "kc|alive3", "a_name": "Lin, Mei",
            "b_uuid": "alive-4", "b_pid": "kc|alive4", "b_name": "Lin, May",
        },
    ]


def test_list_duplicate_pairs_takes_higher_score_on_mismatch(
    base_app, monkeypatch, caplog
):
    """Score desync between the two sides: higher wins, warning logs.

    Both sides write `[score, method]` in the same
    `_set_duplicates_for_pair` call, so a desync only happens after
    a partial-failure mode (e.g. one side's `service.update` failed
    while the other succeeded, then a later sweep rewrote one side
    with a different score). The lister surfaces the live state by
    taking the higher score and its method, and emits a warning so
    the desync is observable.
    """
    svc = NamesSyncService(base_app)

    rec_a = {
        "uuid": "alive-1", "id": "kc|alive1", "name": "Doe, John",
        "props": {"possible_duplicates": {
            "alive-2": [0.70, "family_phonetic+given_fuzzy"],
        }},
    }
    rec_b = {
        "uuid": "alive-2", "id": "kc|alive2", "name": "Doe, Jonathan",
        "props": {"possible_duplicates": {
            "alive-1": [0.95, "family_exact+given_fuzzy"],
        }},
    }

    monkeypatch.setattr(
        svc, "_fetch_records_with_cross_refs",
        lambda *, identity: [rec_a, rec_b],
    )

    with caplog.at_level("WARNING"):
        rows = svc.list_duplicate_pairs()

    assert rows == [{
        "score": 0.95,
        "score_method": "family_exact+given_fuzzy",
        "a_uuid": "alive-1", "a_pid": "kc|alive1", "a_name": "Doe, John",
        "b_uuid": "alive-2", "b_pid": "kc|alive2", "b_name": "Doe, Jonathan",
    }]
    assert any(
        "score mismatch on pair" in r.message
        for r in caplog.records
    )


def test_list_duplicate_pairs_skips_one_sided_reverse_entry(
    base_app, monkeypatch, caplog
):
    """A points at B, but B's `possible_duplicates` does not include A.

    Both records appear in the cross-ref scan (both have non-empty
    `possible_duplicates` maps — B happens to point at C instead),
    so the partner-record-missing branch does *not* fire; the
    reverse-entry-missing branch does. The pair is skipped and a
    warning logs.
    """
    svc = NamesSyncService(base_app)

    rec_a = {
        "uuid": "alive-1", "id": "kc|alive1", "name": "Doe, John",
        "props": {"possible_duplicates": {
            "alive-2": [0.95, "family_exact+given_fuzzy"],
        }},
    }
    rec_b = {
        "uuid": "alive-2", "id": "kc|alive2", "name": "Doe, Jonathan",
        "props": {"possible_duplicates": {
            "alive-3": [0.80, "family_phonetic+given_fuzzy"],
        }},
    }

    monkeypatch.setattr(
        svc, "_fetch_records_with_cross_refs",
        lambda *, identity: [rec_a, rec_b],
    )

    with caplog.at_level("WARNING"):
        rows = svc.list_duplicate_pairs()

    # No symmetric edge survives. (`(alive-2, alive-3)` would also
    # trip the partner-missing branch since `alive-3` is not in the
    # scan; both branches log warnings, no rows are emitted.)
    assert rows == []
    messages = [r.message for r in caplog.records]
    assert any("one-sided possible_duplicates" in m for m in messages)
