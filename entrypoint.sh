#!/bin/bash

# Start crond service
/usr/sbin/cron &

# /usr/local/bin/grype db update

/usr/local/bin/package-scanner "$@"
