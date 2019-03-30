#!/bin/sh

# This script waits for a port to be opened.
# It's meant to be used by chrono's integration tests that need infrastructure (Kafka, Cassandra, ES, etc)
# to be setup and ready (using docker-compose).

wait_for_it() {
	HOSTNAME=$1
	PORT=$2

	while ! nc -z $HOSTNAME $PORT
	do
		echo "waiting for $HOSTNAME:$PORT" to be opened
		sleep 1
	done
	sleep 5
}

wait_for_it $@
