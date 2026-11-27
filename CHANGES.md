# Changes

## 1.1.0 (2026-11-27)

- **Name handling upgrade**: Extensive changes to harmonize name handling across
  KCWorks
  - Persist and compose inverted user_profile.display_name via new
    UserProfileService (Profiles sync, name-parts, backfill-display-names).
  - New version of Jinja user_profile_dict that includes new rich display_name
    field.
  - New UserProfileService
    - brings together shared functions for accessing and manipulating profile
      information (primarily names at present)
    - adds new method to backfill rich display_name for older user records
  - New consolidated RecordCreatibutorSyncService
    - brings together old RecordUsernameSyncService with additional logic to
      update record creatibutor entries with updated display_name strings;
  - New helpers in record_metadata to support shared record creatibutor update
    logic
  - Consolidated user-data CLI under `users` and new `records` subcommands
    - moves name-related commands (`name-parts`) from the kcworks suite into
      this package
    - adds more names functionality (`backfill-display-names`)
    - moves record creatibutor entry update functionality into this package
      (`update_contributors_username`)
    - adds more record creatibutor update functionality
      (`backfill-creatibutor-names`).

## 1.0.1 (2026-11-26)

- Update test to match new upstream behaviour.

## 1.0.0 (2026-03-19)

- First release of major rewrite to support Knowledge Commons' new IDMS based on
  Cilogon and the new KCProfiles app.
- Includes update to use KCProfiles as a login broker for transparent SSO rather
  than communicating directly with cilogon.

## 0.6.1-beta3 (2025-02-25)

- Fixed bug where user profile data was not being updated because comparison
  with initial data was not being made correctly.
- Improved handling of timeout errors when fetching data from the remote source.

## 0.6.0-beta2 (2024-12-19)

- Fixed bug where user profile data was not being updated because comparison
  with initial data was not being made correctly.

## Version 0.0.1

- Initial development version
