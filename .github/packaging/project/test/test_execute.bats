#!/usr/bin/env bats

@test "can run asbackup" {
  asbackup --help
  [ "$?" -eq 0 ]
}