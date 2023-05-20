#!/bin/bash

sleep 60

# Start crond service
/usr/sbin/cron &

/usr/local/bin/grype db update

exec "$@"
