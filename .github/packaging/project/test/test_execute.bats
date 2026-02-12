#!/usr/bin/env bats

@test "can run asbackup" {
  asbackup --help
  [ "$?" -eq 0 ]
}
@test "can run asrestore" {
  asrestore --help
  [ "$?" -eq 0 ]
}