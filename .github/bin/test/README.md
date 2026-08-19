# Post-install smoke tests

`test_execute.bats` runs in CI (`Verify installation`) on every Linux distro and macOS
runner, against the signed package after it is installed. `test_execute.sh` is the same
checks without bats. Both share the assertions in `version_lib.sh`, which documents the
version contract and `EXPECTED_VERSION`, and which the macOS build job also uses to check
the binaries it is about to package.

```
bats .github/bin/test/test_execute.bats
EXPECTED_VERSION=4.5.9-rc1 .github/bin/test/test_execute.sh
```

`test_astools_conf.bats` covers the packaged `astools.conf` handling.
