#!/usr/bin/env bats

@test "can run asbackup" {
  asbackup --help
  [ "$?" -eq 0 ]
}

@test "asbackup reports version" {
  asbackup --version
  [ "$?" -eq 0 ]
}

@test "can run asrestore" {
  asrestore --help
  [ "$?" -eq 0 ]
}

@test "asrestore reports version" {
  asrestore --version
  [ "$?" -eq 0 ]
}