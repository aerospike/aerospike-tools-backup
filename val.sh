#!/bin/bash

/usr/bin/valgrind --leak-resolution=high --track-fds=yes --leak-check=full --track-origins=yes --show-reachable=yes --suppressions=val.supp ${*}

