#!/bin/bash
set -e  

# pick a sensible default 
export BATCHSIGNER_CRON=${BATCHSIGNER_CRON:-*/5 * * * *  python /usr/src/app/batchsigner.py}

/confd -onetime -backend env

echo "Starting Supercronic server"
exec /supercronic /usr/src/app/batchsigner.cron

