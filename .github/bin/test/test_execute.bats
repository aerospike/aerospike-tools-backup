#!/usr/bin/env bats
#
# Post-install smoke tests, run against INSTALLED asbackup and asrestore.
#
# The version tests compare what each installed binary reports against the
# repo's VERSION file, both the Version and the Build line. A package labelled
# with one version but carrying a binary stamped with another (a build step
# that re-links without VERSION and falls back to `git describe`, a stale
# cached binary, or a stale rc binary in a later rc's package) fails here, in
# this repo's own CI, instead of downstream in the aerospike-tools bundle.
#
# Set EXPECTED_VERSION to verify a package built from a revision other than
# the checkout the tests run from; it still has to agree with the VERSION
# file on MAJOR.MINOR.PATCH.

setup() {
  REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)"
  VERSION_FILE="$REPO_ROOT/VERSION"
  load "$BATS_TEST_DIRNAME/version_lib.sh"
}

@test "can run asbackup" {
  run asbackup --help
  [ "$status" -eq 0 ]
}

@test "asbackup reports version" {
  run asbackup --version
  [ "$status" -eq 0 ]
}

@test "asbackup reports the version from the VERSION file" {
  local expected
  expected="$(expected_version "$VERSION_FILE")"

  run asbackup --version
  [ "$status" -eq 0 ]
  echo "expected (from $expected):"
  expected_version_lines "$expected"
  echo "reported:"
  echo "$output"
  assert_version_output "$output" "$expected"
}

@test "can run asrestore" {
  run asrestore --help
  [ "$status" -eq 0 ]
}

@test "asrestore reports version" {
  run asrestore --version
  [ "$status" -eq 0 ]
}

@test "asrestore reports the version from the VERSION file" {
  local expected
  expected="$(expected_version "$VERSION_FILE")"

  run asrestore --version
  [ "$status" -eq 0 ]
  echo "expected (from $expected):"
  expected_version_lines "$expected"
  echo "reported:"
  echo "$output"
  assert_version_output "$output" "$expected"
}
