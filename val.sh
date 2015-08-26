#!/bin/bash

valgrind --leak-resolution=high --track-fds=yes --leak-check=full --show-reachable=yes --suppressions=val.supp ${*}

