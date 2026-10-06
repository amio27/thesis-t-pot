#!/bin/bash
# Import the "Thesis Overview" dashboard into the running Kibana of the thesis stack.
#
# Run on the T-Pot host after the stack is up (Kibana listens on 127.0.0.1:64296).
# - Adds exactly one saved object, id "thesis-overview-dashboard". With
#   overwrite=true only that id can be replaced; the stock T-Pot dashboards are
#   not touched.
# - Needs the stock T-Pot objects (data view "logstash-*" and the "T-Pot Attack Map"
#   map), which tpotinit imports on a fresh install. The script checks for both.
#
# Usage: import_thesis_dashboard.sh [KIBANA_URL]      (default http://127.0.0.1:64296)

myKIBANA="${1:-http://127.0.0.1:64296}"
myFILE="$(cd "$(dirname "$0")" && pwd)/thesis_overview.ndjson"
myMAPID="feacdc40-6d77-11ec-9682-7d3cb7a0cb96"

[ -f "$myFILE" ] || { echo "ERROR: $myFILE not found (run build_thesis_dashboard.py)."; exit 1; }

if ! curl -s -f -o /dev/null "$myKIBANA/api/status"; then
  echo "ERROR: Kibana is not reachable at $myKIBANA."; exit 1
fi

for obj in "index-pattern/logstash-*" "map/$myMAPID"; do
  if ! curl -s -f -o /dev/null -H "kbn-xsrf: true" "$myKIBANA/api/saved_objects/$obj"; then
    echo "ERROR: required stock object '$obj' is missing in Kibana."
    echo "       The stock T-Pot Kibana import has not run, or the object was deleted."
    exit 1
  fi
done

echo "[*] importing $myFILE"
curl -s -X POST "$myKIBANA/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" --form file=@"$myFILE"
echo
echo "[*] open: /kibana/app/dashboards#/view/thesis-overview-dashboard (via the T-Pot web UI)"
