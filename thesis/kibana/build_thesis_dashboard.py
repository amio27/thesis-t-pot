#!/usr/bin/env python3
"""Generate thesis_overview.ndjson, the Kibana saved-objects file for the
"Thesis Overview" dashboard of the T-Pot Thesis Research Edition.

The output holds exactly one saved object, a dashboard with the fixed id
"thesis-overview-dashboard". Its panels are embedded by value (Lens), except the
geographic panel, which references the stock T-Pot map object that the stock
T-Pot Kibana import already creates ("T-Pot Attack Map"). Nothing in the stock
export (docker/tpotinit/dist/etc/objects/kibana_export.ndjson) is read-modified
or overwritten; the per-honeypot dashboards stay as they are.

Usage:  python3 build_thesis_dashboard.py            # rewrites thesis_overview.ndjson
Import: ./import_thesis_dashboard.sh
"""
import json
import os
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "thesis_overview.ndjson")

DASHBOARD_ID = "thesis-overview-dashboard"
INDEX_PATTERN = "logstash-*"                      # id of the stock T-Pot data view
STOCK_MAP_ID = "feacdc40-6d77-11ec-9682-7d3cb7a0cb96"   # "T-Pot Attack Map"

# Honeypots of the thesis edition; values of the Logstash "type" field.
HONEYPOTS = ["Cowrie", "Ddospot", "Dionaea", "Mailoney", "RDPHoneypot", "Sentrypeer", "Tanner"]
# Exact match on the keyword subfield: the stored values are exactly these strings
# (verified against Elasticsearch: Cowrie, Ddospot, Dionaea, Mailoney, RDPHoneypot,
# Sentrypeer, Tanner), so no analyzer is involved.
HP_QUERY = "type.keyword : (" + " or ".join('"%s"' % h for h in HONEYPOTS) + ")"
# Panels on optional fields only look at honeypot documents that carry the field.
PORT_QUERY = HP_QUERY + " and dest_port : *"
USER_QUERY = HP_QUERY + " and username.keyword : *"
PASS_QUERY = HP_QUERY + " and password.keyword : *"

# Attack counts per protocol: (label, KQL). Verified against the live data: Cowrie sets
# "protocol" (ssh / telnet) on every event, but dest_port only on session.connect events,
# so Cowrie is counted by protocol. All other honeypots carry dest_port (the port inside
# the container, e.g. Dionaea SMB is 445 even where the host publishes another port).
PROTOCOLS = [
    ("SSH (Cowrie)", 'type.keyword : "Cowrie" and protocol.keyword : "ssh"'),
    ("Telnet (Cowrie)", 'type.keyword : "Cowrie" and protocol.keyword : "telnet"'),
    ("DNS (Ddospot)", 'type.keyword : "Ddospot" and dest_port : 53'),
    ("NTP (Ddospot)", 'type.keyword : "Ddospot" and dest_port : 123'),
    ("FTP (Dionaea)", 'type.keyword : "Dionaea" and dest_port : 21'),
    ("SMB (Dionaea)", 'type.keyword : "Dionaea" and dest_port : 445'),
    ("MySQL (Dionaea)", 'type.keyword : "Dionaea" and dest_port : 3306'),
    ("SMTP (Mailoney)", 'type.keyword : "Mailoney"'),
    ("RDP (RDPHoneypot)", 'type.keyword : "RDPHoneypot"'),
    ("SIP (Sentrypeer)", 'type.keyword : "Sentrypeer"'),
    ("HTTP (Snare/Tanner)", 'type.keyword : "Tanner"'),
]


def uid(name):
    """Deterministic ids, so regenerating produces a stable file."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "tpot-thesis/" + name))


# ----------------------------------------------------------------- Lens helpers
def count_col(label="Attacks"):
    return {"customLabel": True, "dataType": "number", "isBucketed": False, "label": label,
            "operationType": "count", "scale": "ratio", "sourceField": "___records___",
            "params": {"emptyAsNull": True}}


def unique_col(field, label):
    return {"customLabel": True, "dataType": "number", "isBucketed": False, "label": label,
            "operationType": "unique_count", "scale": "ratio", "sourceField": field,
            "params": {"emptyAsNull": True}}


def terms_col(field, label, metric_id, size=10, data_type="string", exclude=None):
    return {"customLabel": True, "dataType": data_type, "isBucketed": True, "label": label,
            "operationType": "terms", "scale": "ordinal", "sourceField": field,
            "params": {"accuracyMode": True, "exclude": exclude or [], "excludeIsRegex": False,
                       "include": [], "includeIsRegex": False, "missingBucket": False,
                       "orderBy": {"columnId": metric_id, "type": "column"},
                       "orderDirection": "desc", "otherBucket": False,
                       "parentFormat": {"id": "terms"}, "size": size}}


def filters_col(label, filters):
    return {"customLabel": True, "dataType": "string", "isBucketed": True, "label": label,
            "operationType": "filters", "scale": "ordinal",
            "params": {"filters": [{"input": {"language": "kuery", "query": q}, "label": lb}
                                   for lb, q in filters]}}


def date_col(label="Time"):
    return {"customLabel": True, "dataType": "date", "isBucketed": True, "label": label,
            "operationType": "date_histogram", "scale": "interval", "sourceField": "@timestamp",
            "params": {"dropPartials": False, "includeEmptyRows": True, "interval": "auto"}}


def lens(title, vis_type, visualization, layer_id, columns, order, query, ignore_global=False):
    return {
        "title": title, "description": "", "visualizationType": vis_type, "type": "lens",
        "references": [{"type": "index-pattern", "id": INDEX_PATTERN,
                        "name": "indexpattern-datasource-layer-" + layer_id}],
        "state": {
            "visualization": visualization,
            "query": {"query": query, "language": "kuery"},
            "filters": [],
            "datasourceStates": {
                "formBased": {"layers": {layer_id: {
                    "columns": columns, "columnOrder": order, "sampling": 1,
                    "ignoreGlobalFilters": ignore_global, "incompleteColumns": {}}}},
                "indexpattern": {"layers": {}}, "textBased": {"layers": {}}},
            "internalReferences": [], "adHocDataViews": {}},
    }


def metric(name, title, label, col, query, ignore_global=False):
    lid, mid = uid(name + "/layer"), uid(name + "/metric")
    vis = {"layerId": lid, "layerType": "data", "metricAccessor": mid, "showBar": False}
    return lens(title, "lnsMetric", vis, lid, {mid: col}, [mid], query, ignore_global)


def pie(name, title, group_col, query, ignore_global=False, shape="donut"):
    lid, gid, mid = uid(name + "/layer"), uid(name + "/group"), uid(name + "/metric")
    vis = {"shape": shape, "palette": {"name": "kibana_palette", "type": "palette"},
           "layers": [{"layerId": lid, "layerType": "data", "primaryGroups": [gid],
                       "secondaryGroups": [], "metrics": [mid], "numberDisplay": "value",
                       "categoryDisplay": "default", "legendDisplay": "show",
                       "legendPosition": "right", "legendSize": "auto", "legendMaxLines": 1,
                       "nestedLegend": False, "showValuesInLegend": True,
                       "truncateLegend": True, "emptySizeRatio": 0.3}]}
    return lens(title, "lnsPie", vis, lid, {gid: group_col(mid), mid: count_col()},
                [gid, mid], query, ignore_global)


def bar_horizontal(name, title, group_col, query, ignore_global=False):
    lid, gid, mid = uid(name + "/layer"), uid(name + "/group"), uid(name + "/metric")
    vis = {"legend": {"isVisible": False, "position": "right"}, "valueLabels": "hide",
           "preferredSeriesType": "bar_horizontal", "layers": [{
               "layerId": lid, "layerType": "data", "seriesType": "bar_horizontal",
               "xAccessor": gid, "accessors": [mid], "xScaleType": "ordinal",
               "isHistogram": False, "palette": {"name": "kibana_palette", "type": "palette"}}]}
    return lens(title, "lnsXY", vis, lid, {gid: group_col(mid), mid: count_col()},
                [gid, mid], query, ignore_global)


def attacks_over_time(name, title, query):
    lid, did, sid, mid = (uid(name + "/layer"), uid(name + "/date"),
                          uid(name + "/split"), uid(name + "/metric"))
    vis = {"legend": {"isVisible": True, "position": "right", "showSingleSeries": True},
           "valueLabels": "hide", "preferredSeriesType": "bar_stacked",
           "fittingFunction": "None", "axisTitlesVisibilitySettings":
               {"x": False, "yLeft": True, "yRight": True},
           "yTitle": "Attacks",
           "layers": [{"layerId": lid, "layerType": "data", "seriesType": "bar_stacked",
                       "xAccessor": did, "splitAccessor": sid, "accessors": [mid],
                       "xScaleType": "time", "isHistogram": True,
                       "palette": {"name": "kibana_palette", "type": "palette"}}]}
    cols = {did: date_col(), sid: terms_col("type.keyword", "Honeypot", mid, size=len(HONEYPOTS)),
            mid: count_col()}
    return lens(title, "lnsXY", vis, lid, cols, [sid, did, mid], query)


# ------------------------------------------------------------ stock T-Pot objects
# The repo copy of the stock T-Pot export; its objects are the ones tpotinit imports into
# Kibana. The Suricata / p0f panels reuse the stock Lens definitions (fields and queries
# untouched) instead of re-implementing them.
STOCK_EXPORT = os.path.join(HERE, "..", "..", "docker", "tpotinit", "dist", "etc", "objects",
                            "kibana_export.ndjson")
STOCK_P0F_OS = "7a2a7c9f-7cf1-4b0f-86ca-f50768b98a73"        # "P0f OS Distribution" (pie, os.keyword)
STOCK_SURICATA_CATEGORY = "59847638-da13-4308-bd01-22a176c289af"  # "Suricata Alert Category Histogram"


def stock_lens(object_id, title):
    """Stock T-Pot Lens object as a by-value panel that ignores the dashboard filter.

    The stock layers have ignoreGlobalFilters=false and a query such as "type : Suricata",
    so embedded by reference they would be ANDed with the thesis honeypot filter of this
    dashboard and always come back empty. Suricata and p0f are NSM data, not thesis
    honeypots. Setting the layer option "ignore global filters" (the supported Lens setting)
    on a by-value copy leaves fields, query and chart exactly as T-Pot defines them; the
    time range of the dashboard still applies. This is also how the stock ">T-Pot"
    dashboard embeds its own p0f panel (by value).
    """
    with open(STOCK_EXPORT, encoding="utf-8") as fh:
        objs = {o.get("id"): o for o in (json.loads(l) for l in fh if l.strip())}
    obj = objs[object_id]
    assert obj["type"] == "lens", object_id
    attrs = json.loads(json.dumps(obj["attributes"]))       # deep copy
    for layer in attrs["state"]["datasourceStates"]["formBased"]["layers"].values():
        layer["ignoreGlobalFilters"] = True
    attrs.update({"title": title, "type": "lens", "savedObjectId": object_id,
                  "references": obj["references"]})
    # tag references belong to the saved object, not to an embedded panel
    attrs["references"] = [r for r in attrs["references"] if r["type"] == "index-pattern"]
    return attrs


# ------------------------------------------------------------------- dashboard
def build():
    panels = []   # (gridData x, y, w, h, kind, payload)

    def add(x, y, w, h, attributes, title):
        i = uid("panel/" + title)
        panels.append({"type": "lens", "panelIndex": i,
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": i},
                       "embeddableConfig": {"attributes": attributes, "enhancements": {},
                                            "title": title}})

    # Row 1: headline numbers (thesis honeypots only)
    add(0, 0, 16, 7, metric("total", "Total Attacks", "Total Attacks",
                            count_col("Total Attacks"), HP_QUERY), "Total Attacks")
    add(16, 0, 16, 7, metric("uniqip", "Unique Source IPs", "Unique Source IPs",
                             unique_col("src_ip.keyword", "Unique Source IPs"), HP_QUERY),
        "Unique Source IPs")
    add(32, 0, 16, 7, metric("countries", "Source Countries", "Source Countries",
                             unique_col("geoip.country_name.keyword", "Source Countries"), HP_QUERY),
        "Source Countries (distinct)")

    # Row 2: distribution per honeypot, and over time
    add(0, 7, 16, 14, pie("hp", "Attacks by Honeypot",
                          lambda m: terms_col("type.keyword", "Honeypot", m, size=len(HONEYPOTS)),
                          HP_QUERY), "Attacks by Honeypot")
    add(16, 7, 32, 14, attacks_over_time("time", "Attacks over Time", HP_QUERY), "Attacks over Time")

    # Row 3: geographic visualization is the stock T-Pot map, added below (panel type "map")

    # Row 4: where from, where to, which protocol
    add(0, 43, 16, 14, bar_horizontal(
        "country", "Source Countries (Top 10)",
        lambda m: terms_col("geoip.country_name.keyword", "Country", m, size=10), HP_QUERY),
        "Source Countries (Top 10)")
    add(16, 43, 16, 14, bar_horizontal(
        "dport", "Destination Ports (Top 10)",
        lambda m: terms_col("dest_port", "Destination port", m, size=10, data_type="number"), PORT_QUERY),
        "Destination Ports (Top 10)")
    add(32, 43, 16, 14, pie(
        "proto", "Attack Counts per Protocol",
        lambda m: filters_col("Protocol", PROTOCOLS), HP_QUERY),
        "Attack Counts per Protocol")

    # Row 5: network security monitoring. Stock T-Pot visualizations, not limited to the
    # thesis honeypot filter (see stock_lens).
    add(0, 57, 24, 14, stock_lens(STOCK_SURICATA_CATEGORY, "Suricata Alert Categories"),
        "Suricata Alert Categories")
    add(24, 57, 24, 14, stock_lens(STOCK_P0F_OS, "p0f OS Distribution"),
        "p0f OS Distribution")

    # Row 6: credentials where honeypots record them (Cowrie, Dionaea, ...)
    add(0, 71, 24, 14, bar_horizontal(
        "user", "Top Usernames",
        lambda m: terms_col("username.keyword", "Username", m, size=10), USER_QUERY),
        "Top Usernames")
    add(24, 71, 24, 14, bar_horizontal(
        "pass", "Top Passwords",
        lambda m: terms_col("password.keyword", "Password", m, size=10), PASS_QUERY),
        "Top Passwords")

    # Geographic panel: the stock T-Pot map object (attack source + destination heatmaps
    # and attack paths). Its layers follow the dashboard query, i.e. thesis honeypots only.
    map_id = uid("panel/map")
    panels.append({"type": "map", "panelIndex": map_id,
                   "gridData": {"x": 0, "y": 21, "w": 48, "h": 22, "i": map_id},
                   "embeddableConfig": {"isLayerTOCOpen": False, "openTOCDetails": [],
                                        "hiddenLayers": [], "enhancements": {},
                                        "filterByMapExtent": False,
                                        "title": "Geographic Attack Visualization"},
                   "panelRefName": "panel_" + map_id})

    references = [{"id": STOCK_MAP_ID, "name": map_id + ":panel_" + map_id, "type": "map"}]

    dashboard = {
        "id": DASHBOARD_ID,
        "type": "dashboard",
        "coreMigrationVersion": "8.8.0",
        "typeMigrationVersion": "10.3.0",
        "managed": False,
        "attributes": {
            "title": "Thesis Overview",
            "description": "T-Pot Thesis Research Edition overview: Cowrie, Ddospot, Dionaea, "
                           "Mailoney, RDPHoneypot, Sentrypeer, Snare/Tanner, plus Suricata and p0f.",
            "version": 2,
            "timeRestore": True,
            "timeFrom": "now-24h/h",
            "timeTo": "now",
            "refreshInterval": {"pause": True, "value": 60000},
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "syncCursor": True,
                                       "syncTooltips": False, "hidePanelTitles": False}),
            # Dashboard-wide filter: thesis honeypots only. It also drives the map. The
            # The stock Suricata and p0f panels ignore it (ignoreGlobalFilters) because they are not honeypots.
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": HP_QUERY, "language": "kuery"}, "filter": []})},
            "panelsJSON": json.dumps(panels),
        },
        "references": references,
    }
    return dashboard


if __name__ == "__main__":
    with open(OUT, "w") as fh:
        fh.write(json.dumps(build(), separators=(",", ":")) + "\n")
    print("wrote", OUT)
