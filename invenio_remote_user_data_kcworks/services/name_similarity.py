"""Person-name similarity comparator for the names dedup pipeline.

`PersonNameComparator` compares two given-name strings (already known
to share a normalized family token) and returns a similarity score in
`[0.0, 1.0]` suitable for surfacing potential duplicates to a human
reviewer.

The comparator is deliberately tuned for **recall over precision**:
results are reviewed by a human, so over-flagging is cheaper than
under-flagging.

Example:

    comparator = PersonNameComparator()
    result = comparator.compare("J. Q.", "John Quincy")
    # result.score == 1.0
    # result.aligned == (("j", "john"), ("q", "quincy"))
"""

import csv
import re
import unicodedata
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from difflib import SequenceMatcher
from importlib.resources import files

# --- Module-level defaults (overridable via constructor) -----------------

DEFAULT_SUFFIX_TOKENS: frozenset[str] = frozenset({
    "jr",
    "sr",
    "ii",
    "iii",
    "iv",
    "v",
    "phd",
    "md",
    "esq",
})
"""Tokens to drop during tokenization (post-normalization, lowercase)."""

DEFAULT_EQUIVALENCE_PAIRS: frozenset[frozenset[str]] = frozenset({
    # Common English nicknames
    frozenset({"robert", "bob"}),
    frozenset({"robert", "rob"}),
    frozenset({"robert", "bobby"}),
    frozenset({"william", "bill"}),
    frozenset({"william", "billy"}),
    frozenset({"william", "will"}),
    frozenset({"richard", "rick"}),
    frozenset({"richard", "dick"}),
    frozenset({"richard", "rich"}),
    frozenset({"james", "jim"}),
    frozenset({"james", "jimmy"}),
    frozenset({"john", "jack"}),
    frozenset({"john", "johnny"}),
    frozenset({"michael", "mike"}),
    frozenset({"michael", "mickey"}),
    frozenset({"thomas", "tom"}),
    frozenset({"thomas", "tommy"}),
    frozenset({"daniel", "dan"}),
    frozenset({"daniel", "danny"}),
    frozenset({"matthew", "matt"}),
    frozenset({"christopher", "chris"}),
    frozenset({"anthony", "tony"}),
    frozenset({"andrew", "andy"}),
    frozenset({"benjamin", "ben"}),
    frozenset({"nicholas", "nick"}),
    frozenset({"alexander", "alex"}),
    frozenset({"edward", "ed"}),
    frozenset({"edward", "eddie"}),
    frozenset({"joseph", "joe"}),
    frozenset({"joseph", "joey"}),
    frozenset({"katherine", "kate"}),
    frozenset({"katherine", "katie"}),
    frozenset({"katherine", "kathy"}),
    frozenset({"catherine", "cathy"}),
    frozenset({"elizabeth", "liz"}),
    frozenset({"elizabeth", "beth"}),
    frozenset({"elizabeth", "betty"}),
    frozenset({"margaret", "maggie"}),
    frozenset({"margaret", "meg"}),
    frozenset({"margaret", "peggy"}),
    frozenset({"susan", "sue"}),
    frozenset({"barbara", "barb"}),
    frozenset({"jennifer", "jen"}),
    frozenset({"jennifer", "jenny"}),
    frozenset({"patricia", "pat"}),
    frozenset({"patricia", "patty"}),
    frozenset({"deborah", "deb"}),
    frozenset({"deborah", "debbie"}),
    # Common spelling variants the default fuzzy threshold misses
    frozenset({"stephen", "steven"}),
    frozenset({"stephanie", "stefanie"}),
    frozenset({"sean", "shawn"}),
    frozenset({"geoffrey", "jeffrey"}),
})
"""Pairs of normalized tokens treated as equivalent during comparison.

Includes English nicknames and a small set of canonical spelling
variants whose `SequenceMatcher.ratio()` falls below the default fuzzy
threshold. Override via `PersonNameComparator(equivalence_pairs=...)`.
"""

_PUNCT_RE = re.compile(r"[^\w\s-]", re.UNICODE)
"""Strips punctuation while preserving Unicode word chars, whitespace, hyphens."""

_VENDORED_VARIANTS_PACKAGE = "invenio_remote_user_data_kcworks.data.given_name_variants"
_VENDORED_VARIANTS_FILENAME = "givenname_similar_names.csv"

_DEFAULT_EQUIVALENCE_INDEX: dict[str, frozenset[str]] | None = None
"""Process-wide cache of the vendored equivalence index.

Populated lazily on first need by `_get_default_equivalence_index()`.
None until first access. The load takes roughly 1 s and consumes
approximately 230 MB resident; we therefore defer it until a
`PersonNameComparator` actually needs to consult equivalences (i.e.,
the first `_compatible()` call in the dedup pipeline). Web workers
that never run dedup never pay this cost.
"""


def _load_vendored_equivalence_index() -> dict[str, frozenset[str]]:
    """Build an inverted `name -> {canonical_root, ...}` index from the CSV.

    Each CSV row has the shape `canonical,space-separated variants`.
    The canonical column is treated as the root; every variant is
    indexed back to that root, and the canonical is also indexed to
    itself. Two tokens are equivalent iff their root sets intersect.

    Returns:
        An inverted index mapping each token to its canonical-root set.
    """
    index: dict[str, set[str]] = defaultdict(set)
    resource = files(_VENDORED_VARIANTS_PACKAGE).joinpath(_VENDORED_VARIANTS_FILENAME)
    with resource.open(encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row:
                continue
            canonical = row[0]
            variants = row[1] if len(row) > 1 else ""
            index[canonical].add(canonical)
            for variant in variants.split():
                index[variant].add(canonical)
    return {key: frozenset(roots) for key, roots in index.items()}


def _get_default_equivalence_index() -> dict[str, frozenset[str]]:
    """Return the lazily-loaded vendored equivalence index.

    Populates the module-level cache on first call (~1 s, ~230 MB).
    Subsequent calls are O(1). The double-load race that occurs when
    two threads hit this simultaneously is harmless: both produce
    identical dicts and the second assignment wins.
    """
    global _DEFAULT_EQUIVALENCE_INDEX
    if _DEFAULT_EQUIVALENCE_INDEX is None:
        _DEFAULT_EQUIVALENCE_INDEX = _load_vendored_equivalence_index()
    return _DEFAULT_EQUIVALENCE_INDEX


def _pairs_to_index(
    pairs: Iterable[Iterable[str]],
) -> dict[str, frozenset[str]]:
    """Convert explicit equivalence pairs into the inverted-root format.

    Each pair gets its own synthetic root, so equivalence is NOT
    transitively closed across pairs. This preserves the prior
    `frozenset({a, b}) in equivalence_pairs` semantics: tokens are
    equivalent only if they appear together in some explicit pair.

    Returns:
        An inverted index mapping each token to its synthetic-root set.
    """
    by_token: dict[str, set[str]] = defaultdict(set)
    for pair in pairs:
        members = sorted(set(pair))
        if len(members) < 2:
            continue
        root = "\x00pair:" + "|".join(members)
        for member in members:
            by_token[member].add(root)
    return {key: frozenset(roots) for key, roots in by_token.items()}


@dataclass(frozen=True)
class NameComparison:
    """Result of `PersonNameComparator.compare()`.

    Fields:
        score: Similarity in `[0.0, 1.0]`. Higher = more similar.
        aligned: Tuple of (token_from_a, token_from_b) pairs that the
            order-preserving alignment matched. Useful for explaining
            a flagged pair to a human reviewer.
        tokens_a: The normalized tokens extracted from the first input.
        tokens_b: The normalized tokens extracted from the second input.
    """

    score: float
    aligned: tuple[tuple[str, str], ...]
    tokens_a: tuple[str, ...]
    tokens_b: tuple[str, ...]


class PersonNameComparator:
    """Order-preserving, abbreviation-aware given-name similarity.

    The comparator tokenizes each input given-name string, then finds
    the longest order-preserving alignment between the two token lists
    using a relaxed compatibility relation:

    - Two **initial** tokens (length 1) are compatible if equal.
    - An **initial** and a **word** are compatible if the word starts
      with the initial.
    - Two **word** tokens are compatible if they are equal, share at
      least one canonical root in the equivalence index (nickname or
      spelling variant), or share a `difflib.SequenceMatcher.ratio()`
      at or above `word_fuzzy_threshold`.

    The equivalence index defaults to a vendored ~70k-row table of
    cross-language given-name variants (see
    `data/given_name_variants/`). The table is loaded lazily on the
    first `_compatible()` call (~1 s, ~230 MB resident) and cached
    process-wide, so constructing a `PersonNameComparator` is cheap
    and importers / web workers that never invoke comparison pay
    nothing. Pass `equivalence_pairs=...` to bypass the vendored
    table entirely (e.g., in tests or for an opinionated small set).

    FIXME: the vendored equivalence table is genealogy-derived and
    *will* generate false positives in the dedup feed. The clearest
    pathology is combo-name back-propagation: rows like
    `annemarie -> ann anne anna marie ...` cause `_compatible()`
    to treat unrelated tokens such as `mary` and `ann` as
    equivalent. A spot-check finds ~15% of arbitrary common
    Western-name pairs share at least one canonical root through
    such compounds. Cross-language cognates (john/hans/ivan/ian via
    `Yohanan`) are *not* the problem; combo-name compounds are.
    Mitigations to consider, in roughly increasing invasiveness:
    (1) treat equivalence-index hits as a softer signal than exact
        equality by routing them through a separate, lower
        `equivalence_score_bonus` instead of returning
        `compatible=True` outright (requires changing the
        boolean `_compatible()` API into a graded score and
        threading that through the LCS DP);
    (2) filter the CSV at vendor-load time, dropping rows whose
        canonical key looks like a known compound
        (e.g. contains two short-name substrings);
    (3) replace the in-process index with a curated/cleaned
        upstream dataset.

    The final score combines two ratios over the alignment count:

        coverage     = matched / min(m, n)   # how much of shorter list aligned
        completeness = matched / max(m, n)   # how much of longer list aligned
        score = w * coverage + (1 - w) * completeness   # default w = 0.7

    The coverage-weighted formula favors recall when one record carries
    fewer given-name tokens than the other (e.g., "Mary" vs "Pauline
    Mary"). False positives are acceptable because results surface for
    human review rather than auto-merging.

    Empty-given-name pairs (when either side has no extractable tokens)
    return `empty_score` (default 0.3) so they still surface for review
    when their family token already collides.
    """

    def __init__(
        self,
        *,
        word_fuzzy_threshold: float = 0.80,
        coverage_weight: float = 0.7,
        empty_score: float = 0.3,
        equivalence_pairs: Iterable[Iterable[str]] | None = None,
        suffix_tokens: Iterable[str] | None = None,
    ) -> None:
        """Construct a comparator.

        Args:
            word_fuzzy_threshold: Minimum `SequenceMatcher.ratio()` for
                two word tokens (length >= 2) to be considered
                compatible. Range `[0.0, 1.0]`. Lower = more permissive.
            coverage_weight: Weight `w` in the score formula
                `w * coverage + (1 - w) * completeness`. Range
                `[0.0, 1.0]`. Higher values favor recall when token
                counts differ.
            empty_score: Score returned when either input tokenizes to
                an empty list (e.g., one side has no given name).
            equivalence_pairs: Iterable of token pairs to treat as
                equivalent. Each pair may be a tuple, list, or set of
                two normalized (lowercase, diacritic-folded) tokens.
                When omitted (`None`), the comparator uses the
                vendored ~70k-row variants table loaded lazily on
                first comparison. Pass an explicit iterable to bypass
                the vendored table entirely (handy for tests).
            suffix_tokens: Tokens to drop during tokenization
                (e.g., "jr", "phd"). Defaults to
                `DEFAULT_SUFFIX_TOKENS`.

        Raises:
            ValueError: If any numeric argument falls outside `[0, 1]`.
        """
        if not 0.0 <= word_fuzzy_threshold <= 1.0:
            raise ValueError("word_fuzzy_threshold must be in [0, 1]")
        if not 0.0 <= coverage_weight <= 1.0:
            raise ValueError("coverage_weight must be in [0, 1]")
        if not 0.0 <= empty_score <= 1.0:
            raise ValueError("empty_score must be in [0, 1]")
        self._word_fuzzy_threshold = word_fuzzy_threshold
        self._coverage_weight = coverage_weight
        self._empty_score = empty_score
        self._suffix_tokens = (
            frozenset(suffix_tokens)
            if suffix_tokens is not None
            else DEFAULT_SUFFIX_TOKENS
        )
        self._equivalence_index: dict[str, frozenset[str]] | None = (
            _pairs_to_index(equivalence_pairs)
            if equivalence_pairs is not None
            else None
        )

    def compare(self, given_a: str, given_b: str) -> NameComparison:
        """Compare two given-name strings.

        Args:
            given_a: First given-name string (any case, may include
                diacritics, periods, hyphens, suffixes).
            given_b: Second given-name string.

        Returns:
            A `NameComparison` containing the score, the recovered
            alignment, and the normalized token lists.
        """
        tokens_a = tuple(self.tokenize(given_a, self._suffix_tokens))
        tokens_b = tuple(self.tokenize(given_b, self._suffix_tokens))
        if not tokens_a or not tokens_b:
            return NameComparison(
                score=self._empty_score,
                aligned=(),
                tokens_a=tokens_a,
                tokens_b=tokens_b,
            )
        aligned = self._align(tokens_a, tokens_b)
        m, n = len(tokens_a), len(tokens_b)
        coverage = len(aligned) / min(m, n)
        completeness = len(aligned) / max(m, n)
        score = (
            self._coverage_weight * coverage
            + (1 - self._coverage_weight) * completeness
        )
        return NameComparison(
            score=round(score, 4),
            aligned=tuple(aligned),
            tokens_a=tokens_a,
            tokens_b=tokens_b,
        )

    @staticmethod
    def tokenize(
        given: str,
        suffixes: frozenset[str] = DEFAULT_SUFFIX_TOKENS,
    ) -> list[str]:
        """Normalize and split a given-name string into tokens.

        Pipeline: NFKD-decompose to fold diacritics and compatibility
        forms, lowercase, strip punctuation (preserving whitespace and
        hyphens), split on whitespace and hyphens, drop empties and any
        token in `suffixes`.

        Args:
            given: Raw given-name string.
            suffixes: Lowercase tokens to drop (e.g., "jr", "phd").

        Returns:
            Ordered list of normalized tokens. Empty if `given` is
            empty or contains only suffixes/punctuation.
        """
        if not given:
            return []
        folded = "".join(
            c
            for c in unicodedata.normalize("NFKD", given)
            if not unicodedata.combining(c)
        )
        folded = _PUNCT_RE.sub("", folded.lower())
        raw: list[str] = []
        for chunk in folded.split():
            raw.extend(p for p in chunk.split("-") if p)
        return [t for t in raw if t not in suffixes]

    def _align(
        self,
        a: tuple[str, ...],
        b: tuple[str, ...],
    ) -> list[tuple[str, str]]:
        """Order-preserving longest compatible alignment via DP.

        Standard LCS recurrence using `_compatible` as the equality
        relation. O(m * n) time and space. Backtracks once to recover
        one alignment for explainability.

        Args:
            a: Normalized tokens from the first input.
            b: Normalized tokens from the second input.

        Returns:
            List of `(token_a, token_b)` pairs in input order.
        """
        m, n = len(a), len(b)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if self._compatible(a[i - 1], b[j - 1]):
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
        aligned: list[tuple[str, str]] = []
        i, j = m, n
        while i > 0 and j > 0:
            if (
                self._compatible(a[i - 1], b[j - 1])
                and dp[i][j] == dp[i - 1][j - 1] + 1
            ):
                aligned.append((a[i - 1], b[j - 1]))
                i -= 1
                j -= 1
            elif dp[i - 1][j] >= dp[i][j - 1]:
                i -= 1
            else:
                j -= 1
        aligned.reverse()
        return aligned

    def _compatible(self, t1: str, t2: str) -> bool:
        """Check whether two normalized tokens are considered the same.

        Returns:
            True iff `t1` and `t2` satisfy at least one compatibility
            rule (equal, initial-prefix, share a canonical root in the
            equivalence index, or fuzzy similarity at or above
            `word_fuzzy_threshold`).
        """
        if t1 == t2:
            return True
        len1, len2 = len(t1), len(t2)
        if len1 == 1 and len2 == 1:
            return False
        if len1 == 1:
            return t2.startswith(t1)
        if len2 == 1:
            return t1.startswith(t2)
        index = self._equivalence_index
        if index is None:
            index = _get_default_equivalence_index()
            self._equivalence_index = index
        roots1 = index.get(t1)
        if roots1:
            roots2 = index.get(t2)
            if roots2 and not roots1.isdisjoint(roots2):
                return True
        return SequenceMatcher(None, t1, t2).ratio() >= self._word_fuzzy_threshold
