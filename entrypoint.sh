#!/bin/bash

sleep 60

# Start crond service
/usr/sbin/crond

/usr/local/bin/grype db update

