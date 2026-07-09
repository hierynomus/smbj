# SMB3 Directory Leases

smbj supports **SMB3 directory leases** — letting a client cache directory listings and trust
them until the server pushes a lease break. It's the same mechanism Windows and Apple's SMB
client use, and the feature Samba added in 4.22 (`smb3 directory leases`). The payoff: repeated
`list()` of an unchanged directory is served from memory with **zero** `QUERY_DIRECTORY`
round-trips.

## What this adds
- **Create-context layer** — `SMB2CreateContext` (de)serialization (`mssmb2.messages.create`).
- **Lease model** — `LeaseKey`, `SMB2LeaseState`/`Flags`, `SMB2OplockLevel`, and the `RqLs`
  V1/V2 create-context request writer + response parser.
- **CREATE wiring** — `SMB2CreateRequest`/`Response` carry contexts + the oplock/lease level
  (backward compatible; the no-context path is byte-identical).
- **Negotiate** — `SmbConfig` advertises `LEASING`/`DIRECTORY_LEASING` (default on).
- **Open-with-lease** — `DiskShare.openDirectory`/`list()` request a V2 RH directory lease;
  `LeaseManager`/`LeaseEntry` track leases per connection, with ParentLeaseKey threading.
- **Lease-break handling** — server-pushed `OPLOCK_BREAK` (the all-FF form) is routed off the
  read thread, parsed, epoch-checked, acknowledged, and used to invalidate the cache.
- **Directory cache** — `LeasedDirectoryCache` serves repeat listings from memory and evicts on
  break, via a dedicated kept-open handle the application never closes.

The change is backward compatible: when the server does not grant a directory lease, behaviour
is unchanged and every `list()` issues `QUERY_DIRECTORY` as before.

## Testing
Unit tests:

```bash
./gradlew test
```

The live integration tests need an SMB3 server with directory leases enabled (for example
Samba ≥ 4.22 with `smb3 directory leases = yes`). They are skipped unless `SMBJ_IT_HOST` is
set:

```bash
SMBJ_IT_HOST=<host> SMBJ_IT_PORT=445 SMBJ_IT_USER=<user> SMBJ_IT_PASS=<password> \
  ./gradlew integrationTest --tests "*DirectoryLease*IntegrationTest"
```
