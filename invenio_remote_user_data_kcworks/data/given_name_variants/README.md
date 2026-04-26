# Given-name variants (vendored)

This directory vendors a comprehensive given-name variants table used by
`invenio_remote_user_data_kcworks.services.name_similarity.PersonNameComparator`
to recognize nickname / spelling-variant / cross-language equivalences when
scoring candidate duplicate `Names` records.

## Files

- `givenname_similar_names.csv` (~16 MB, 70,000 rows)
  - One row per canonical given name. Format:
    `"<canonical>","<variant1> <variant2> <variant3> ..."`
  - All entries are lowercase ASCII.
  - Includes English diminutives (e.g. `robert` → `bob`, `bobby`, ...) **and**
    cross-language cognates (e.g. `john` → `juan`, `johann`, `jean`, `ivan`,
    `giovanni`, `joão`, `seán`, ...).
- `LICENSE` — Apache License 2.0 (verbatim copy of the upstream LICENSE file).

## Provenance

- Upstream: <https://github.com/tfmorris/Names>
- Original path: `search/src/main/resources/givenname_similar_names.csv`
- Upstream commit (last touch on this file at vendor time):
  `a20a85a14e047e7a9a954d0f8d29cd17fc172b63` (2012-01-10)
- Vendored: 2026-04-25

The upstream repository is itself a clone of the now-removed
`DallanQ/Names` project (see upstream README). The variants table was
constructed by augmenting Ancestry.com's most-frequent given-name pairs
with hand-curated additions sourced from `behindthename.com` (via
`givenname_behindthename.txt`), `WeRelate.org` (via
`givenname_werelate.txt`), and a small hand-edited nickname list.

## License

The data is licensed under Apache-2.0 by the upstream author. Updates
incorporated from `WeRelate.org` are additionally subject to that site's
Creative Commons Attribution-ShareAlike license; if we ever locally modify
or extend this file, those modifications should be treated as CC-BY-SA
when redistributed.

## Update procedure

To refresh against a newer upstream commit:

1. `curl -sL https://raw.githubusercontent.com/tfmorris/Names/<commit>/search/src/main/resources/givenname_similar_names.csv -o givenname_similar_names.csv`
2. `curl -sL https://raw.githubusercontent.com/tfmorris/Names/<commit>/LICENSE -o LICENSE`
3. Update the upstream commit hash and vendor date in this README.
4. Re-run `tests/api/test_name_similarity.py` and the dedup test suite.
