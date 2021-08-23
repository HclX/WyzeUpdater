#!/bin/sh

echo "Starting wyzehacks.sh"

# Run telnetd if not yet
while true;
do
    sleep 10
    if pgrep -f telnetd >/dev/null 2>&1; then
        continue
    fi

    echo "Starting telnetd..."
    telnetd
done
