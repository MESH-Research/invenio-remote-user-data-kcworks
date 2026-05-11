"""Unit tests for `PersonNameComparator`."""

import pytest

from invenio_remote_user_data_kcworks.services.name_similarity import (
    DEFAULT_EQUIVALENCE_PAIRS,
    NameComparison,
    PersonNameComparator,
)


@pytest.fixture
def comparator() -> PersonNameComparator:
    """Return a `PersonNameComparator` configured with all defaults."""
    return PersonNameComparator()


class TestTokenize:
    """Tests for `PersonNameComparator.tokenize`."""

    def test_lowercases(self):
        """Lowercase ASCII input produces a single lowercase token."""
        assert PersonNameComparator.tokenize("John") == ["john"]

    def test_folds_diacritics(self):
        """NFKD-fold strips combining accents from Latin characters."""
        assert PersonNameComparator.tokenize("François") == ["francois"]
        assert PersonNameComparator.tokenize("Müller") == ["muller"]

    def test_splits_on_whitespace_and_hyphen(self):
        """Whitespace and hyphens both split tokens; apostrophes are stripped."""
        assert PersonNameComparator.tokenize("Mary-Jane O'Brien") == [
            "mary",
            "jane",
            "obrien",
        ]

    def test_strips_periods(self):
        """Periods are stripped; surrounding tokens remain intact."""
        assert PersonNameComparator.tokenize("J. Q.") == ["j", "q"]

    def test_drops_default_suffixes(self):
        """Default suffix tokens (jr, iii, phd, ...) are dropped."""
        assert PersonNameComparator.tokenize("John Jr.") == ["john"]
        assert PersonNameComparator.tokenize("John III") == ["john"]
        assert PersonNameComparator.tokenize("John PhD") == ["john"]

    def test_handles_full_width(self):
        """NFKD compatibility decomposition folds full-width characters."""
        assert PersonNameComparator.tokenize("Ｊｏｈｎ") == ["john"]

    def test_handles_compatibility_ligatures(self):
        """The "ﬁ" ligature decomposes under NFKD to "fi"."""
        assert PersonNameComparator.tokenize("ﬁsher") == ["fisher"]

    def test_empty_inputs(self):
        """Empty, whitespace-only, and punctuation-only inputs yield empty lists."""
        assert PersonNameComparator.tokenize("") == []
        assert PersonNameComparator.tokenize("   ") == []
        assert PersonNameComparator.tokenize("...") == []


class TestExactAndStructuralCompare:
    """Tests for exact matches and full alignments across initial/word forms."""

    def test_exact_match(self, comparator: PersonNameComparator):
        """Identical inputs score 1.0 with the single token aligned."""
        result = comparator.compare("John", "John")
        assert result.score == 1.0
        assert result.aligned == (("john", "john"),)

    def test_initials_vs_words_full_alignment(self, comparator: PersonNameComparator):
        """All-initials vs all-words score 1.0 when each initial prefixes its word."""
        # ["j", "q"] vs ["john", "quincy"] -> 2/2 aligned
        assert comparator.compare("J. Q.", "John Quincy").score == 1.0

    def test_mixed_initial_and_word(self, comparator: PersonNameComparator):
        """Mixed initial/word patterns align element-wise."""
        # ["john", "q"] vs ["j", "quincy"] -> 2/2 aligned
        assert comparator.compare("John Q.", "J. Quincy").score == 1.0


class TestRecallOrientedScoring:
    """Tests of the coverage-weighted formula on size-asymmetric cases.

    The default `coverage_weight=0.7` should produce high scores when
    the shorter side is fully covered by the longer side.
    """

    def test_missing_middle_name(self, comparator: PersonNameComparator):
        """Missing-middle case scores 0.85 (full coverage of shorter side)."""
        # ["john"] vs ["john", "quincy"]: matched=1, m=1, n=2
        # coverage=1.0, completeness=0.5 -> 0.7 + 0.15 = 0.85
        assert comparator.compare("John", "John Quincy").score == pytest.approx(0.85)

    def test_mary_in_second_position_of_other(self, comparator: PersonNameComparator):
        """A single given-name token aligns with the same token at any position."""
        result = comparator.compare("Mary", "Pauline Mary")
        assert result.score == pytest.approx(0.85)
        assert result.aligned == (("mary", "mary"),)

    def test_mary_with_initial_first_in_other(self, comparator: PersonNameComparator):
        """Single token aligns past a leading initial on the other side."""
        result = comparator.compare("Mary", "P. Mary")
        assert result.score == pytest.approx(0.85)

    def test_mary_with_initial_second_in_other(self, comparator: PersonNameComparator):
        """Single token aligns past a trailing initial on the other side."""
        result = comparator.compare("Mary", "Mary J.")
        assert result.score == pytest.approx(0.85)

    def test_single_given_against_long_name(self, comparator: PersonNameComparator):
        """One token vs three tokens still scores 0.8 when fully covered."""
        # ["mary"] vs ["mary", "anne", "catherine"]: matched=1, m=1, n=3
        # coverage=1.0, completeness=1/3 -> 0.7 + 0.1 = 0.8
        result = comparator.compare("Mary", "Mary Anne Catherine")
        assert result.score == pytest.approx(0.8)


class TestVariantHandling:
    """Tests for diacritic folding, equivalence-table lookup, and fuzzy matching."""

    def test_diacritic_fold(self, comparator: PersonNameComparator):
        """Names differing only by accents score 1.0."""
        assert comparator.compare("François", "Francois").score == 1.0

    def test_diacritic_on_secondary_token(self, comparator: PersonNameComparator):
        """Diacritics anywhere in the multi-token form are folded equally."""
        assert comparator.compare("Maria José", "Maria Jose").score == 1.0

    def test_spelling_variant_via_equivalence_table(
        self, comparator: PersonNameComparator
    ):
        """Equivalence-table entries override the fuzzy threshold for known pairs."""
        # Stephen/Steven is in DEFAULT_EQUIVALENCE_PAIRS because its
        # SequenceMatcher.ratio() (~0.77) is below the default 0.80
        # fuzzy threshold.
        assert comparator.compare("Stephen", "Steven").score == 1.0

    def test_spelling_variant_via_fuzzy(self, comparator: PersonNameComparator):
        """Pairs above the fuzzy threshold are compatible without a table entry."""
        # ratio("catherine", "katherine") ~ 0.89, above 0.80 threshold.
        assert comparator.compare("Catherine", "Katherine").score == 1.0

    def test_nickname_short_form(self, comparator: PersonNameComparator):
        """Common English nicknames in the default table score 1.0."""
        assert comparator.compare("Robert", "Bob").score == 1.0
        assert comparator.compare("William", "Bill").score == 1.0
        assert comparator.compare("Elizabeth", "Liz").score == 1.0


class TestNonMatching:
    """Tests for cases where pairs should NOT score as full matches."""

    def test_initial_vs_unrelated_word(self, comparator: PersonNameComparator):
        """An initial that does not prefix the other word is incompatible."""
        # ["j"] vs ["mary"]: incompatible
        result = comparator.compare("J.", "Mary")
        assert result.score == 0.0

    def test_partial_match_same_length(self, comparator: PersonNameComparator):
        """Same-length pairs with one aligned token score 0.5."""
        # ["john", "a"] vs ["john", "b"]: matched=1 (john), m=n=2
        # coverage=0.5, completeness=0.5 -> 0.5
        assert comparator.compare("John A.", "John B.").score == 0.5

    def test_order_is_preserved(self, comparator: PersonNameComparator):
        """Reversed token order cannot align both tokens (LCS is order-preserving)."""
        # ["john", "david"] vs ["david", "john"]: at most one alignable
        assert comparator.compare("John David", "David John").score == 0.5

    def test_mary_anne_vs_anne_marie(self, comparator: PersonNameComparator):
        """Combo-name connections in the vendored index align both tokens.

        With the default vendored equivalence index, both `mary <-> anne`
        (via `annemarie`, `marianne`, `maryann`) and `mary <-> marie`
        (via direct variant rows) share canonical roots, so LCS finds
        the alignment `((mary, anne), (anne, marie))` and scores 1.0.
        """
        result = comparator.compare("Mary Anne", "Anne Marie")
        assert result.score == 1.0
        assert result.aligned == (("mary", "anne"), ("anne", "marie"))


class TestEmptyHandling:
    """Tests for the `empty_score` fallback when tokenization yields no tokens."""

    def test_one_side_empty_returns_empty_score(self, comparator: PersonNameComparator):
        """Empty input on either side returns the configured `empty_score`."""
        assert comparator.compare("", "John").score == 0.3
        assert comparator.compare("John", "").score == 0.3

    def test_both_sides_empty(self, comparator: PersonNameComparator):
        """Both sides empty also returns `empty_score`."""
        assert comparator.compare("", "").score == 0.3

    def test_only_suffixes(self, comparator: PersonNameComparator):
        """Inputs of only suffix tokens tokenize to nothing and use `empty_score`."""
        assert comparator.compare("Jr. III", "John").score == 0.3


class TestCustomization:
    """Tests for constructor parameter overrides."""

    def test_raised_threshold_filters_fuzzy_matches(self):
        """Raising `word_fuzzy_threshold` rejects previously-accepted fuzzy pairs.

        Uses synthetic non-name tokens so the vendored equivalence
        index cannot route around the threshold; the comparator's
        only path to "compatible" for this pair is the fuzzy ratio.
        """
        c = PersonNameComparator(word_fuzzy_threshold=0.95)
        # ratio("xyzzy", "xyzzr") == 0.80, < 0.95, no longer compatible
        assert c.compare("Xyzzy", "Xyzzr").score == 0.0

    def test_custom_equivalence_pairs_only(self):
        """Supplying `equivalence_pairs` replaces the entire default table."""
        c = PersonNameComparator(equivalence_pairs=[("xyzzy", "plugh")])
        # Robert/Bob no longer treated as equivalent
        assert c.compare("Robert", "Bob").score == 0.0
        # Custom pair recognized
        assert c.compare("Xyzzy", "Plugh").score == 1.0

    def test_coverage_weight_zero_collapses_to_completeness(self):
        """`coverage_weight=0` reduces the score to pure completeness."""
        c = PersonNameComparator(coverage_weight=0.0)
        # ["mary"] vs ["pauline", "mary"]: matched=1, completeness=0.5
        assert c.compare("Mary", "Pauline Mary").score == 0.5

    def test_coverage_weight_one_ignores_size_difference(self):
        """`coverage_weight=1` makes the score depend only on shorter-side coverage."""
        c = PersonNameComparator(coverage_weight=1.0)
        # ["mary"] vs ["pauline", "mary", "anne"]: matched=1, coverage=1
        assert c.compare("Mary", "Pauline Mary Anne").score == 1.0

    def test_custom_empty_score(self):
        """`empty_score=0.0` returns 0 when either side has no tokens."""
        c = PersonNameComparator(empty_score=0.0)
        assert c.compare("", "John").score == 0.0

    def test_custom_suffixes(self):
        """Supplying `suffix_tokens` replaces the default suffix set."""
        c = PersonNameComparator(suffix_tokens={"jr"})
        # "phd" no longer dropped
        assert c.compare("John PhD", "John PhD").score == 1.0
        result = c.compare("John PhD", "John")
        # ["john", "phd"] vs ["john"]: matched=1, m=2, n=1
        # coverage=1.0, completeness=0.5 -> 0.85
        assert result.score == pytest.approx(0.85)

    def test_validates_threshold_range(self):
        """Numeric arguments outside `[0, 1]` raise `ValueError`."""
        with pytest.raises(ValueError):
            PersonNameComparator(word_fuzzy_threshold=1.5)
        with pytest.raises(ValueError):
            PersonNameComparator(coverage_weight=-0.1)
        with pytest.raises(ValueError):
            PersonNameComparator(empty_score=2.0)


class TestComparisonResultShape:
    """Tests that `NameComparison` carries normalized tokens and the alignment."""

    def test_returns_tokens_and_alignment(self, comparator: PersonNameComparator):
        """`compare` returns a `NameComparison` with tokens and aligned pairs."""
        result = comparator.compare("J. Q.", "John Quincy")
        assert isinstance(result, NameComparison)
        assert result.tokens_a == ("j", "q")
        assert result.tokens_b == ("john", "quincy")
        assert result.aligned == (("j", "john"), ("q", "quincy"))

    def test_alignment_explains_partial_match(self, comparator: PersonNameComparator):
        """The alignment field shows exactly which tokens contributed to the score."""
        result = comparator.compare("John A.", "John B.")
        assert result.aligned == (("john", "john"),)


def test_default_equivalence_pairs_are_normalized():
    """Every default equivalence pair must be lowercase, length-2, no whitespace."""
    for pair in DEFAULT_EQUIVALENCE_PAIRS:
        assert len(pair) == 2
        for token in pair:
            assert token == token.lower()
            assert " " not in token
