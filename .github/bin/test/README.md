# Post-install smoke tests

`test_execute.bats` runs in CI (`Verify installation`) on every Linux distro and macOS
runner, against the signed package after it is installed. It checks that asbackup and
asrestore run and that **the version each reports matches the repo's `VERSION` file**, so a
package labelled with one version but carrying a binary stamped with another fails here
instead of downstream in the aerospike-tools bundle.

Both printed lines are compared. `print_version()` splits the embedded string on `-`, so
`4.5.9-rc1` reports `Version 4.5.9` / `Build rc1` and a bare `4.5.9` reports no `Build` line
at all. Asserting the `Build` line is what catches a stale rc binary inside a later rc's
package, where the two differ only by the iteration.

```
bats .github/bin/test/test_execute.bats
```

`test_execute.sh` is the same checks without bats; both share the assertions in
`version_lib.sh`, which the macOS build job also uses to check the binaries it is about to
package.

Both accept `EXPECTED_VERSION` to verify a package built from a revision other than the
checkout you run them from. CI sets it to the workflow's `BUILD_VERSION`, which on a dev
build carries the commit sha instead of the `rcN` in the file. It still has to agree with
the VERSION file on `MAJOR.MINOR.PATCH`, so a run wired to the wrong workflow output fails
rather than testing against whatever it was handed.

```
EXPECTED_VERSION=4.5.9-rc1 .github/bin/test/test_execute.sh
```

`test_astools_conf.bats` covers the packaged `astools.conf` handling.
