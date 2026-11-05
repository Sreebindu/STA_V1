import os
import json
import math
from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ---------------- CONFIG ----------------

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
ES_API_KEY = os.getenv("ES_API_KEY")
ES_USER = os.getenv("ELASTIC_USER")
ES_PASSWORD = os.getenv("ELASTIC_PASSWORD")

# Granular Indexes
PCAP_METADATA_INDEX = "pcap-metadata"  # Full PCAP metadata (superset of captures + dashboard)
PCAP_IPS_INDEX = "pcap-ips"            # Per-PCAP IP rows in the unified nested ips field
GLOBAL_DASHBOARD_SINKHOLE_ID = 1
PCAP_DNS_INDEX = "pcap-dns"            # Granular DNS/URL records
PCAP_FILES_INDEX = "pcap-files"        # File transfer records
IP_INTEL_INDEX = "ip-intelligence"     # One record per unique IP ΓÇö WHOIS, ports, DNSBL, OS
ZEEK_CONN_INDEX = "zeek-conn"          # Cached Zeek conn.log summaries and connection logs
DNS_REQUESTS_INDEX = "dns-requests"    # Per-URL requests with connected client IPs + geo (from http.log)
MAP_COUNTRY_CACHE_INDEX = "map-country-cache"  # Materialized view: per-country IP/packet/capture counts
GEO_BREAKDOWN_CACHE_INDEX = "geo-breakdown-cache"  # Materialized view: country/city/isp packets+connections

_COUNTRY_ALIASES = {
    "in": "India",
    "ind": "India",
    "republic of india": "India",
    "us": "United States",
    "usa": "United States",
    "united states of america": "United States",
    "america": "United States",
    "gb": "United Kingdom",
    "uk": "United Kingdom",
    "united kingdom of great britain and northern ireland": "United Kingdom",
    "great britain": "United Kingdom",
    "britain": "United Kingdom",
    "england": "United Kingdom",
    "scotland": "United Kingdom",
    "wales": "United Kingdom",
    "northern ireland": "United Kingdom",
    "cn": "China",
    "people's republic of china": "China",
    "ru": "Russia",
    "russian federation": "Russia",
    "kr": "South Korea",
    "korea, republic of": "South Korea",
    "vn": "Vietnam",
    "socialist republic of viet nam": "Vietnam",
    "tr": "Turkey",
    "republic of turkiye": "Turkey",
    "republic of türkiye": "Turkey",
    "tw": "Taiwan",
    "taiwan, province of china": "Taiwan",
    "ir": "Iran",
    "islamic republic of iran": "Iran",
    "sy": "Syria",
    "syrian arab republic": "Syria",
    "bo": "Bolivia",
    "plurinational state of bolivia": "Bolivia",
    "tz": "Tanzania",
    "united republic of tanzania": "Tanzania",
    "md": "Moldova",
    "republic of moldova": "Moldova",
    "cz": "Czech Republic",
    "czechia": "Czech Republic",
    "mk": "North Macedonia",
    "republic of north macedonia": "North Macedonia",
    "ci": "Cote d'Ivoire",
    "cote d'ivoire": "Cote d'Ivoire",
    "côte d'ivoire": "Cote d'Ivoire",
    "cd": "Democratic Republic of the Congo",
    "congo, the democratic republic of the": "Democratic Republic of the Congo",
    "cg": "Republic of the Congo",
    "republic of the congo": "Republic of the Congo",
}

SCRIPTED_METRIC_INIT_SCRIPT = "state.map = [:]"
SCRIPTED_METRIC_COMBINE_SCRIPT = "return state.map"
SCRIPTED_METRIC_REDUCE_SCRIPT = (
    "def out = [:]; for (s in states) { for (e in s.entrySet()) { "
    "out[e.getKey()] = (out.containsKey(e.getKey()) ? out[e.getKey()] : 0) + e.getValue(); "
    "} } return out"
)

# ---------------- CONNECTION ----------------
_es_instance = None

def get_es():
    global _es_instance
    if _es_instance is not None:
        return _es_instance

    try:
        auth = None
        if ES_API_KEY:
            auth = {"api_key": ES_API_KEY}
        elif ES_USER and ES_PASSWORD:
            auth = (ES_USER, ES_PASSWORD)
        # Allow connection without authentication for localhost

        es = Elasticsearch(
            ES_HOST,
            basic_auth=auth if isinstance(auth, tuple) else None,
            api_key=auth["api_key"] if isinstance(auth, dict) else None,
            verify_certs=False,
            request_timeout=60,
            max_retries=3,
            retry_on_timeout=True,
            connections_per_node=5,
            http_compress=True,
        )

        if es.ping():
            _es_instance = es
            print(f"Connected to Elasticsearch at {ES_HOST}")
        else:
            print(f"Cannot ping Elasticsearch at {ES_HOST}")
            _es_instance = None
    except Exception as e:
        print(f"ES connection error: {e}")
        _es_instance = None

    return _es_instance

# ---------------- INDEX CREATION ----------------
def create_granular_indexes():
    es = get_es()
    if not es: return

    dashboard_mapping = {
        "mappings": {
            "properties": {
                "pcap_id":               {"type": "keyword"},
                "sinkhole_id":           {"type": "integer"},
                "file_id":               {"type": "keyword"},
                "file_name":             {"type": "keyword"},
                "pcap_filename":         {"type": "keyword"},
                "analysis_timestamp":    {"type": "date"},
                "start_time_utc":        {"type": "date"},
                "end_time_utc":          {"type": "date"},
                "duration_seconds":      {"type": "double"},
                "attack_duration_seconds": {"type": "double"},
                "file_size":             {"type": "long"},
                "total_packets":         {"type": "long"},
                "exact_pcap_packets":    {"type": "long"},
                "total_connections":     {"type": "long"},
                "total_dns_queries":     {"type": "long"},
                "total_http_requests":   {"type": "long"},
                "total_bytes":           {"type": "long"},
                "unique_sources":        {"type": "long"},
                "malware_type":          {"type": "keyword"},
                "infected_host":         {"type": "keyword"},
                "reputation_status":     {"type": "keyword"},
                "transport_breakdown": {"properties": {
                    "label": {"type": "keyword"},
                    "value": {"type": "long"}
                }},
                "application_breakdown": {"properties": {
                    "label": {"type": "keyword"},
                    "value": {"type": "long"}
                }},
                "direction_breakdown": {"properties": {
                    "label": {"type": "keyword"},
                    "value": {"type": "long"}
                }},
                "time_series": {"properties": {
                    "label": {"type": "date"},
                    "value": {"type": "long"}
                }},
                "top_dns_domains": {"properties": {
                    "label": {"type": "keyword"},
                    "value": {"type": "long"}
                }},
                "top_url_domains": {"properties": {
                    "label": {"type": "keyword"},
                    "value": {"type": "long"}
                }},
                "protocols": {"properties": {
                    "protocol": {"type": "keyword"},
                    "packet_count": {"type": "long"}
                }},
                "ports": {"properties": {
                    "port": {"type": "keyword"},
                    "protocol": {"type": "keyword"},
                    "usage": {"type": "long"}
                }},
                "user_agents": {"properties": {
                    "user_agent": {"type": "keyword"}
                }},
                "ftp_session": {"properties": {
                    "source_ip":       {"type": "keyword"},
                    "destination_ip":  {"type": "keyword"},
                    "port":            {"type": "keyword"},
                    "username":        {"type": "keyword"},
                    "command":         {"type": "keyword"},
                    "file_transferred":{"type": "keyword"},
                    "data_type":       {"type": "keyword"}
                }},
            },
            "dynamic": False
        }
    }

    # 2. GRANULAR IPS
    ips_mapping = {
        "mappings": {
            "properties": {
                "pcap_id": {"type": "keyword"},
                "ips": {
                    "type": "nested",
                    "properties": {
                        "ip": {"type": "ip"},
                        "packet_count": {"type": "integer"},
                        "country": {"type": "keyword"},
                        "city": {"type": "keyword"},
                        "isp": {"type": "keyword"},
                        "latitude": {"type": "double"},
                        "longitude": {"type": "double"},
                        "location": {"type": "geo_point"},
                        "is_internal": {"type": "boolean"},
                        "internal_connection_count": {"type": "integer"}
                    }
                }
            }
        }
    }

    # 3. GRANULAR DNS/URLS
    dns_mapping = {
        "mappings": {
            "properties": {
                "pcap_id": {"type": "keyword"},
                "record_type": {"type": "keyword"},
                "pcap_filename": {"type": "keyword"},
                "analysis_timestamp": {"type": "date"},
                "domain_count": {"type": "integer"},
                "domains": {
                    "type": "nested",
                    "properties": {
                        "domain": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "record_type": {"type": "keyword"},
                        "count": {"type": "integer"},
                        "is_ioc": {"type": "boolean"}
                    }
                }
            }
        }
    }

    files_mapping = {
        "mappings": {
            "properties": {
                "pcap_id": {"type": "keyword"},
                "filename": {"type": "keyword"},
                "type": {"type": "keyword"},
                "protocol": {"type": "keyword"},
                "file_size": {"type": "long"}
            }
        }
    }

    intel_mapping = {
        "mappings": {
            "properties": {
                "ip":             {"type": "ip"},
                "scan_time":      {"type": "date"},
                "enriched_at":    {"type": "date"},
                "last_seen":      {"type": "date"},
                "source":         {"type": "keyword"},
                "status":         {"type": "keyword"},
                "rdns":           {"type": "keyword"},
                "asn":            {"type": "keyword"},
                "proxy_type":     {"type": "keyword"},
                "location":       {"type": "geo_point"},
                "geo": {"properties": {
                    "country":   {"type": "keyword"},
                    "city":      {"type": "keyword"},
                    "isp":       {"type": "keyword"},
                    "latitude":  {"type": "double"},
                    "longitude": {"type": "double"},
                }},
                "whois": {"properties": {
                    "org":           {"type": "keyword"},
                    "name":          {"type": "keyword"},
                    "cidr":          {"type": "keyword"},
                    "network_owner": {"type": "keyword"},
                    "registered":    {"type": "keyword"},
                    "registrar":     {"type": "keyword"},
                    "website":       {"type": "keyword"},
                    "tld":           {"type": "keyword"},
                    "email":         {"type": "keyword"},
                    "phone":         {"type": "keyword"},
                    "address":       {"type": "text"},
                }},
                "dnsbl": {"properties": {
                    "listed":         {"type": "boolean"},
                    "total_listings": {"type": "integer"},
                }},
                "os_info": {"properties": {
                    "best_match":  {"type": "keyword"},
                    "confidence": {"type": "float"},
                    "reliable":   {"type": "boolean"},
                }},
                "hostnames": {"type": "keyword"},
                "ports": {"properties": {
                    "port":     {"type": "integer"},
                    "protocol": {"type": "keyword"},
                    "service":  {"type": "keyword"},
                    "state":    {"type": "keyword"},
                }},
            },
            "dynamic": True,
        }
    }

    conn_logs_mapping = {
        "mappings": {
            "properties": {
                "pcap_id":    {"type": "keyword"},
                "ts":         {"type": "double"},
                "id.orig_h":  {"type": "ip"},
                "id.resp_h":  {"type": "ip"},
                "id.resp_p":  {"type": "integer"},
                "proto":      {"type": "keyword"},
                "service":    {"type": "keyword"},
                "duration":   {"type": "double"},
                "orig_bytes": {"type": "long"},
                "conn_state": {"type": "keyword"},
            }
        }
    }

    dns_requests_mapping = {
        "mappings": {
            "properties": {
                "pcap_id":            {"type": "keyword"},
                "url":                {"type": "keyword"},
                "host":               {"type": "keyword"},
                "uri":                {"type": "keyword"},
                "connected_ip_count": {"type": "integer"},
                "request_count":      {"type": "integer"},
                "connected_ips": {"properties": {
                    "ip":        {"type": "ip"},
                    "isp":       {"type": "keyword"},
                    "latitude":  {"type": "double"},
                    "longitude": {"type": "double"},
                }},
                "analysis_timestamp": {"type": "date"},
            }
        }
    }

    for idx, mapping in [
        (PCAP_METADATA_INDEX, dashboard_mapping),
        (PCAP_IPS_INDEX, ips_mapping),
        (PCAP_DNS_INDEX, dns_mapping),
        (PCAP_FILES_INDEX, files_mapping),
        (IP_INTEL_INDEX, intel_mapping),
        (ZEEK_CONN_INDEX, conn_logs_mapping),
        (DNS_REQUESTS_INDEX, dns_requests_mapping),
    ]:
        if not es.indices.exists(index=idx):
            es.indices.create(index=idx, body=mapping)
            print(f"Created Index: {idx}")

# ---------------- INDEXING ----------------


def get_dashboard_document(pcap_id):
    es = get_es()
    if not es:
        return None

    try:
        doc = es.get(index=PCAP_METADATA_INDEX, id=pcap_id)["_source"]
        if doc.get("file_id") == pcap_id or doc.get("pcap_id") == pcap_id:
            return doc
    except NotFoundError:
        pass
    except Exception:
        pass

    try:
        res = es.search(
            index=PCAP_METADATA_INDEX,
            body={"query": {"term": {"file_id": pcap_id}}},
            size=1,
        )
        hits = res.get("hits", {}).get("hits", [])
        if hits:
            doc = hits[0].get("_source", {})
            if doc.get("file_id") == pcap_id or doc.get("pcap_id") == pcap_id:
                return doc
    except Exception:
        pass

    return None


def get_latest_dashboard_document(sinkhole_id=None):
    es = get_es()
    if not es:
        return None
    try:
        query = {"match_all": {}} if sinkhole_id is None else {"term": {"sinkhole_id": sinkhole_id}}
        res = es.search(
            index=PCAP_METADATA_INDEX,
            body={"query": query},
            size=1,
            sort=[{"analysis_timestamp": {"order": "desc", "unmapped_type": "date"}}]
        )
        hits = res.get("hits", {}).get("hits", [])
        if hits:
            return hits[0].get("_source")
        return None
    except Exception:
        return None


def get_pcap_ids_for_sinkhole(sinkhole_id, es_client=None):
    """Return PCAP IDs associated with a sinkhole set."""
    es = es_client or get_es()
    if not es:
        return []
    try:
        res = es.search(index=PCAP_METADATA_INDEX, body={
            "size": 10000,
            "_source": ["pcap_id"],
            "query": {"term": {"sinkhole_id": sinkhole_id}},
        })
        return [
            hit["_source"]["pcap_id"]
            for hit in res.get("hits", {}).get("hits", [])
            if hit.get("_source", {}).get("pcap_id")
        ]
    except Exception as e:
        print(f"get_pcap_ids_for_sinkhole error: {e}")
        return []


def get_pcap_ip_docs(pcap_ids, es_client=None, source_fields=None):
    """Collect and normalize IP records from all documents for each PCAP."""
    if not pcap_ids:
        return {}
    es = es_client or get_es()
    if not es:
        return {}

    response = es.search(
        index=PCAP_IPS_INDEX,
        body={
            "query": {"terms": {"pcap_id": pcap_ids}},
            "_source": source_fields or ["pcap_id", "ips", "external_ips", "internal_ips"],
            "size": 1000,
        },
        scroll="2m",
    )
    documents = {}
    scroll_id = response.get("_scroll_id")

    def add_records(target, field, records):
        by_ip = target.setdefault(field, {})
        for record in records or []:
            ip = record.get("ip")
            if ip:
                by_ip[ip] = record

    def add_source(pcap_id, source):
        target = documents.setdefault(
            pcap_id,
            {"pcap_id": pcap_id, "external_ips": {}, "internal_ips": {}},
        )
        if "ips" in source:
            records = source.get("ips") or []
            add_records(
                target,
                "external_ips",
                [record for record in records if record.get("is_internal") is False],
            )
            add_records(
                target,
                "internal_ips",
                [record for record in records if record.get("is_internal") is True],
            )
        add_records(target, "external_ips", source.get("external_ips"))
        add_records(target, "internal_ips", source.get("internal_ips"))

    try:
        while True:
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                break
            for hit in hits:
                source = hit.get("_source", {})
                pcap_id = source.get("pcap_id") or hit.get("_id")
                add_source(pcap_id, source)

            if not scroll_id:
                break
            response = es.scroll(scroll_id=scroll_id, scroll="2m")
            scroll_id = response.get("_scroll_id", scroll_id)
    finally:
        if scroll_id:
            es.clear_scroll(scroll_id=scroll_id)

    missing_pcap_ids = [pcap_id for pcap_id in pcap_ids if pcap_id not in documents]
    for offset in range(0, len(missing_pcap_ids), 500):
        response = es.mget(
            index=PCAP_IPS_INDEX,
            ids=missing_pcap_ids[offset:offset + 500],
            source_includes=source_fields,
        )
        for doc in response.get("docs", []):
            if not doc.get("found"):
                continue
            pcap_id = doc.get("_id")
            add_source(pcap_id, doc.get("_source", {}))

    for document in documents.values():
        for field in ("external_ips", "internal_ips"):
            document[field] = list(document[field].values())
    return documents


# ---------------- SEARCH & AGGREGATIONS ----------------



def count_observed_ips(pcap_ip_docs):
    unique = set()
    for source in (pcap_ip_docs or {}).values():
        for entry in (source.get("external_ips") or []) + (source.get("internal_ips") or []):
            ip = entry.get("ip")
            if ip:
                unique.add(ip)
    return len(unique)


def _count_observed_ips_in_es(es, pcap_ids):
    if not pcap_ids:
        return 0

    response = es.search(
        index=PCAP_IPS_INDEX,
        body={
            "query": {"terms": {"pcap_id": pcap_ids}},
            "size": 0,
            "aggs": {
                "unique_ips": {
                    "scripted_metric": {
                        "init_script": "state.ips = new HashSet()",
                        "map_script": """
                            def source = params._source;
                            if (source.ips != null) {
                                for (def item : source.ips) {
                                    if (item.ip != null) state.ips.add(item.ip.toString());
                                }
                            }
                            for (def field : ['external_ips', 'internal_ips']) {
                                if (source[field] != null) {
                                    for (def item : source[field]) {
                                        if (item.ip != null) state.ips.add(item.ip.toString());
                                    }
                                }
                            }
                        """,
                        "combine_script": "return state.ips",
                        "reduce_script": """
                            def unique = new HashSet();
                            for (def shard_ips : states) {
                                if (shard_ips != null) unique.addAll(shard_ips);
                            }
                            return unique.size();
                        """,
                    }
                }
            },
        },
    )
    return int(
        response.get("aggregations", {})
        .get("unique_ips", {})
        .get("value", 0)
        or 0
    )


def get_repository_stats(sinkhole_id=None, pcap_ip_docs=None, include_observed_ips=True):
    """Repository-wide stats, optionally scoped to a single sinkhole set.

    When sinkhole_id is None, stats cover the whole repository and observed_ips
    is the global unique-IP count from ip-intelligence. When scoped, totals are
    aggregated only over that sinkhole's pcaps and observed_ips is the number of
    distinct IPs seen across those pcaps (from pcap-ips).
    """
    es = get_es()
    if not es:
        return {
            "total_pcaps": 0,
            "observed_ips": 0,
            "repository_size": 0,
            "traffic_volume": 0,
        }

    meta_query = {"match_all": {}} if sinkhole_id is None else {"term": {"sinkhole_id": sinkhole_id}}

    scoped_pcap_ids = []
    try:
        capture_agg = es.search(
            index=PCAP_METADATA_INDEX,
            body={
                "query": meta_query,
                "size": 10000 if sinkhole_id is not None and include_observed_ips and pcap_ip_docs is None else 0,
                "_source": ["pcap_id"] if sinkhole_id is not None and include_observed_ips and pcap_ip_docs is None else False,
                "track_total_hits": True,
                "aggs": {
                    "repository_size": {"sum": {"field": "total_bytes"}},
                    "traffic_volume": {"sum": {"field": "total_packets"}},
                },
            },
        )
        total_hits = capture_agg.get("hits", {}).get("total", 0)
        total_pcaps = int(total_hits.get("value", 0) if isinstance(total_hits, dict) else total_hits)
        aggs = capture_agg.get("aggregations", {})
        repository_size = int(aggs.get("repository_size", {}).get("value", 0) or 0)
        traffic_volume = int(aggs.get("traffic_volume", {}).get("value", 0) or 0)
        if sinkhole_id is not None and pcap_ip_docs is None:
            scoped_pcap_ids = [
                h["_source"].get("pcap_id")
                for h in capture_agg.get("hits", {}).get("hits", [])
                if h.get("_source", {}).get("pcap_id")
            ]
    except Exception:
        total_pcaps = 0
        repository_size = 0
        traffic_volume = 0

    try:
        if not include_observed_ips:
            observed_ips = 0
        elif sinkhole_id is None:
            observed_ips = int(es.count(index=IP_INTEL_INDEX, body={"query": {"match_all": {}}}).get("count", 0))
        else:
            if pcap_ip_docs is None:
                observed_ips = _count_observed_ips_in_es(es, scoped_pcap_ids)
            else:
                observed_ips = count_observed_ips(pcap_ip_docs)
    except Exception:
        observed_ips = 0

    return {
        "total_pcaps": total_pcaps,
        "observed_ips": observed_ips,
        "repository_size": repository_size,
        "traffic_volume": traffic_volume,
    }

def get_global_aggregation(sinkhole_id=None):
    return get_global_aggregation_fast(sinkhole_id=sinkhole_id)


def _get_intel_ip_counts(sinkhole_id=None):
    """Return geo groups with real packet counts from external entries in pcap-ips."""
    from aggregations import aggregate_geo_from_es
    es = get_es()
    if not es:
        return {}, {}, {}
    try:
        pcap_ids = get_pcap_ids_for_sinkhole(sinkhole_id, es) if sinkhole_id is not None else None
        result = aggregate_geo_from_es(es, PCAP_IPS_INDEX, pcap_ids=pcap_ids)
        def _to_dict(key):
            return {item["name"]: {"packets": item["packets"], "connections": item["count"]} for item in result.get(key, [])}
        return _to_dict("countries"), _to_dict("cities"), _to_dict("isps")
    except Exception as e:
        print(f"_get_intel_ip_counts error: {e}")
        return {}, {}, {}


def get_ip_breakdown(pcap_id=None, sinkhole_id=None):
    es = get_es()
    if not es: return {"isps": [], "countries": [], "cities": []}

    if pcap_id:
        from aggregations import aggregate_geo_from_external_ips
        try:
            return aggregate_geo_from_external_ips(es, pcap_id)
        except Exception as e:
            print(f"get_ip_breakdown (pcap) error: {e}")
            return {"isps": [], "countries": [], "cities": []}

    try:
        countries, cities, isps = _get_intel_ip_counts(sinkhole_id=sinkhole_id)
        def _sort(d):
            return sorted([{"name": k, "packets": v["packets"], "connections": v["connections"]} for k, v in d.items()], key=lambda x: (x["packets"], x["connections"]), reverse=True)
        return {"countries": _sort(countries), "cities": _sort(cities), "isps": _sort(isps)}
    except Exception as e:
        print(f"get_ip_breakdown (global) error: {e}")
        return {"isps": [], "countries": [], "cities": []}


def get_report_details(report_type, value):
    """Global per-IP breakdown for a country/isp, aggregated on pcap-ips.

    Single nested aggregation: filter external IPs by the country/ISP value,
    group by IP, sum packet_count across all pcaps, and pull geo via top_hits.
    Packet counts come straight from pcap-ips (no ip-intelligence round-trip).
    """
    import urllib.parse
    from aggregations import sort_ip_rows

    es = get_es()
    if not es: return []

    if '%' in value:
        value = urllib.parse.unquote(value)

    field = {'isp': 'ips.isp', 'country': 'ips.country'}.get(report_type.lower())
    if not field: return []

    try:
        res = es.search(index=PCAP_IPS_INDEX, body={
            "size": 0,
            "aggs": {"ext": {"nested": {"path": "ips"}, "aggs": {
                "external_only": {"filter": {"bool": {"filter": [
                    {"term": {"ips.is_internal": False}},
                    {"term": {field: value}},
                ]}}, "aggs": {
                    "by_ip": {
                        "terms": {"field": "ips.ip", "size": 10000},
                        "aggs": {
                            "packets": {"sum": {"field": "ips.packet_count"}},
                            "lat": {"max": {"field": "ips.latitude"}},
                            "lon": {"max": {"field": "ips.longitude"}},
                        }
                    }
                }}
            }}}
        })
        buckets = (res.get("aggregations", {})
                      .get("ext", {})
                      .get("external_only", {})
                      .get("by_ip", {})
                      .get("buckets", []))
        rows = []
        for b in buckets:
            packets = int(b.get("packets", {}).get("value", 0) or 0)
            rows.append({
                "ip":           b["key"],
                "packet_count": packets,
                "latitude":     b.get("lat", {}).get("value"),
                "longitude":    b.get("lon", {}).get("value"),
            })
        return sort_ip_rows(rows)
    except Exception as e:
        print(f"get_report_details error: {e}")
        return []


def _pcap_ids_for_sinkhole(es, sinkhole_id):
    """Return the list of pcap_ids belonging to a sinkhole set."""
    return get_pcap_ids_for_sinkhole(sinkhole_id, es)


def list_isps_for_sinkhole(sinkhole_id, page=1, per_page=50, search=""):
    """List ISPs (with IP + packet counts) across a sinkhole set's pcaps, from pcap-ips."""
    es = get_es()
    if not es:
        return {"isps": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

    per_page = max(1, min(per_page, 500))
    try:
        pcap_ids = _pcap_ids_for_sinkhole(es, sinkhole_id)
        if not pcap_ids:
            return {"isps": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

        res = es.search(index=PCAP_IPS_INDEX, body={
            "size": 0,
            "query": {"terms": {"pcap_id": pcap_ids}},
            "aggs": {"ext": {"nested": {"path": "ips"}, "aggs": {
                "external_only": {"filter": {"term": {"ips.is_internal": False}}, "aggs": {
                    "by_isp": {
                        "terms": {"field": "ips.isp", "size": 10000, "order": {"_count": "desc"}},
                        "aggs": {
                            "ips": {"cardinality": {"field": "ips.ip"}},
                            "packets": {"sum": {"field": "ips.packet_count"}},
                        },
                    }
                }}
            }}},
        })
    except Exception as e:
        print(f"list_isps_for_sinkhole error: {e}")
        return {"isps": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

    buckets = res["aggregations"]["ext"]["external_only"]["by_isp"]["buckets"]
    if search:
        s = search.lower()
        buckets = [b for b in buckets if b["key"] and s in b["key"].lower()]

    isps = [{
        "isp": b["key"],
        "ip_count": int(b["ips"]["value"]),
        "packet_count": int(b["packets"]["value"] or 0),
    } for b in buckets]

    total = len(isps)
    total_pages = math.ceil(total / per_page) if per_page > 0 else 0
    start = (page - 1) * per_page
    return {"isps": isps[start:start + per_page], "total": total,
            "page": page, "per_page": per_page, "total_pages": total_pages}


def get_ips_by_isp_for_sinkhole(sinkhole_id, isp, page=1, per_page=100):
    """Return IPs for a given ISP within a sinkhole set, aggregated from pcap-ips.

    Each record: ip, packet_count (summed across the set's pcaps), latitude,
    longitude. Paginated.
    """
    es = get_es()
    if not es:
        return {"isp": isp, "ips": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

    import urllib.parse
    if isp and '%' in isp:
        isp = urllib.parse.unquote(isp)

    per_page = max(1, min(per_page, 1000))
    try:
        pcap_ids = _pcap_ids_for_sinkhole(es, sinkhole_id)
        if not pcap_ids:
            return {"isp": isp, "ips": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

        res = es.search(index=PCAP_IPS_INDEX, body={
            "size": 0,
            "query": {"terms": {"pcap_id": pcap_ids}},
            "aggs": {"ext": {"nested": {"path": "ips"}, "aggs": {
                "external_only": {"filter": {"bool": {"filter": [
                    {"term": {"ips.is_internal": False}},
                    {"term": {"ips.isp": isp}},
                ]}}, "aggs": {
                    "by_ip": {
                        "terms": {"field": "ips.ip", "size": 10000},
                        "aggs": {
                            "packets": {"sum": {"field": "ips.packet_count"}},
                            "lat": {"max": {"field": "ips.latitude"}},
                            "lon": {"max": {"field": "ips.longitude"}},
                        },
                    }
                }}
            }}},
        })
    except Exception as e:
        print(f"get_ips_by_isp_for_sinkhole error: {e}")
        return {"isp": isp, "ips": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

    buckets = (res.get("aggregations", {}).get("ext", {})
                  .get("external_only", {}).get("by_ip", {}).get("buckets", []))
    rows = [{
        "ip": b["key"],
        "packet_count": int(b["packets"]["value"] or 0),
        "isp": isp,
        "latitude": b.get("lat", {}).get("value"),
        "longitude": b.get("lon", {}).get("value"),
    } for b in buckets]
    rows.sort(key=lambda r: r["packet_count"], reverse=True)

    total = len(rows)
    total_pages = math.ceil(total / per_page) if per_page > 0 else 0
    start = (page - 1) * per_page
    return {"isp": isp, "ips": rows[start:start + per_page], "total": total,
            "page": page, "per_page": per_page, "total_pages": total_pages}


def get_isps_for_domain_in_sinkhole(sinkhole_id, domain, page=1, per_page=50):
    """Return the ISPs of the IPs that connected to a domain within a sinkhole set.

    Source is dns-requests (per-URL docs from http.log). The domain's connected
    IPs are merged (deduped by ip, each carrying its isp) across the set's pcaps,
    then grouped by ISP with the distinct-IP count and the IPs themselves.
    """
    es = get_es()
    if not es:
        return {"domain": domain, "isps": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

    import urllib.parse
    if domain and '%' in domain:
        domain = urllib.parse.unquote(domain)

    per_page = max(1, min(per_page, 500))
    try:
        pcap_ids = _pcap_ids_for_sinkhole(es, sinkhole_id)
        if not pcap_ids:
            return {"domain": domain, "isps": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

        res = es.search(index=DNS_REQUESTS_INDEX, body={
            "size": 1000,
            "_source": ["host", "connected_ips"],
            "query": {"bool": {"must": [
                {"term": {"host": domain}},
                {"terms": {"pcap_id": pcap_ids}},
            ]}},
        })
    except Exception as e:
        print(f"get_isps_for_domain_in_sinkhole error: {e}")
        return {"domain": domain, "isps": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

    # Merge connected IPs across the domain's docs, deduped by ip.
    ip_records = {}
    for hit in res["hits"]["hits"]:
        for c in hit["_source"].get("connected_ips") or []:
            ip = c.get("ip")
            if ip and ip not in ip_records:
                ip_records[ip] = c

    # Group deduped IPs by ISP.
    isp_map = {}
    for c in ip_records.values():
        isp = c.get("isp") or "Unknown"
        entry = isp_map.setdefault(isp, {"isp": isp, "ip_count": 0, "ips": []})
        entry["ip_count"] += 1
        entry["ips"].append({
            "ip": c.get("ip"),
            "latitude": c.get("latitude"),
            "longitude": c.get("longitude"),
        })

    isps = sorted(isp_map.values(), key=lambda x: x["ip_count"], reverse=True)
    total = len(isps)
    total_pages = math.ceil(total / per_page) if per_page > 0 else 0
    start = (page - 1) * per_page
    return {"domain": domain, "isps": isps[start:start + per_page], "total": total,
            "page": page, "per_page": per_page, "total_pages": total_pages}


def get_pcap_report_details(pcap_id, report_type, value):
    import urllib.parse
    from aggregations import filter_ips_by_field, sort_ip_rows

    es = get_es()
    if not es: return []

    if '%' in value:
        value = urllib.parse.unquote(value)

    field = {'isp': 'isp', 'country': 'country'}.get(report_type.lower())
    if not field: return []

    try:
        filtered = filter_ips_by_field(es, pcap_id, field, value)
        return sort_ip_rows(filtered)
    except Exception as e:
        print(f"get_pcap_report_details error: {e}")
        return []

# IP intelligence helpers (stored in IP_INTEL_INDEX ΓÇö one record per unique IP)

def get_pcaps_for_ip(ip):
    """Return list of {pcap_id, filename} for all PCAPs containing the given IP."""
    es = get_es()
    if not es:
        return []
    try:
        res = es.search(index=PCAP_IPS_INDEX, body={
            "_source": ["pcap_id"],
            "size": 10000,
            "query": {"nested": {
                "path": "ips",
                "query": {"bool": {"filter": [
                    {"term": {"ips.ip": ip}},
                    {"term": {"ips.is_internal": False}},
                ]}},
            }}
        })
        pcap_ids = [h["_source"]["pcap_id"] for h in res["hits"]["hits"] if h["_source"].get("pcap_id")]
        if not pcap_ids:
            return []
        mget_res = es.mget(index=PCAP_METADATA_INDEX, body={"ids": pcap_ids}, _source=["pcap_id", "pcap_filename", "file_name"])
        result = []
        for doc in mget_res["docs"]:
            if doc.get("found"):
                src = doc["_source"]
                result.append({
                    "pcap_id": src.get("pcap_id") or doc["_id"],
                    "filename": src.get("pcap_filename") or src.get("file_name") or doc["_id"],
                })
        return result
    except Exception as e:
        print(f"get_pcaps_for_ip error: {e}")
        return []


def get_pcaps_for_ips_bulk(ip_list):
    """Return {ip: [{pcap_id, filename}]} for all IPs in one ES query."""
    es = get_es()
    if not es or not ip_list:
        return {}
    try:
        res = es.search(index=PCAP_IPS_INDEX, body={
            "size": 10000,
            "_source": ["pcap_id", "ips.ip", "ips.is_internal"],
            "query": {"nested": {
                "path": "ips",
                "query": {"bool": {"filter": [
                    {"terms": {"ips.ip": ip_list}},
                    {"term": {"ips.is_internal": False}},
                ]}},
            }},
        })
        ip_pcap_map = {}
        for hit in res.get("hits", {}).get("hits", []):
            pid = hit.get("_source", {}).get("pcap_id")
            if not pid:
                continue
            for item in hit.get("_source", {}).get("ips", []):
                ip = item.get("ip")
                if ip in ip_list and item.get("is_internal") is False:
                    ip_pcap_map.setdefault(ip, [])
                    if pid not in ip_pcap_map[ip]:
                        ip_pcap_map[ip].append(pid)
        # collect all unique pcap_ids
        all_pcap_ids = list({pid for pids in ip_pcap_map.values() for pid in pids})
        if not all_pcap_ids:
            return {}
        mget_res = es.mget(index=PCAP_METADATA_INDEX, body={"ids": all_pcap_ids}, _source=["pcap_id", "pcap_filename", "file_name"])
        pcap_info = {}
        for doc in mget_res["docs"]:
            if doc.get("found"):
                src = doc["_source"]
                pcap_info[doc["_id"]] = {
                    "pcap_id": src.get("pcap_id") or doc["_id"],
                    "filename": src.get("pcap_filename") or src.get("file_name") or doc["_id"],
                }
        return {
            ip: [pcap_info[pid] for pid in pids if pid in pcap_info]
            for ip, pids in ip_pcap_map.items()
        }
    except Exception as e:
        print(f"get_pcaps_for_ips_bulk error: {e}")
        return {}


def enrich_rows_with_pcap_appearance_data(rows, pcaps_map=None):
    """Add PCAP filename list/count to report rows for UI and PDF rendering."""
    if not rows:
        return rows

    if pcaps_map is None:
        ip_list = [row.get("ip") for row in rows if isinstance(row, dict) and row.get("ip")]
        pcaps_map = get_pcaps_for_ips_bulk(ip_list) if ip_list else {}

    for row in rows:
        if not isinstance(row, dict):
            continue
        ip = row.get("ip")
        pcap_entries = pcaps_map.get(ip, []) if isinstance(pcaps_map, dict) else []
        if not isinstance(pcap_entries, list):
            pcap_entries = []

        normalized_entries = []
        for entry in pcap_entries:
            if not isinstance(entry, dict):
                continue
            normalized = dict(entry)
            filename = (
                normalized.get("filename")
                or normalized.get("pcap_filename")
                or normalized.get("file_name")
                or normalized.get("pcap_id")
                or normalized.get("id")
            )
            if filename:
                normalized["filename"] = filename
            normalized_entries.append(normalized)

        pcap_names = [entry.get("filename") for entry in normalized_entries if entry.get("filename")]
        pcap_names_text = ", ".join(pcap_names) if pcap_names else ""
        pcap_count = len(pcap_names)
        row["_pcaps"] = normalized_entries
        row["pcap_names"] = pcap_names_text
        row["pcap_name"] = pcap_names_text
        row["pcapName"] = pcap_names_text
        row["pcapNames"] = pcap_names_text
        row["pcap_appearances"] = pcap_names_text
        row["pcap_appearance_names"] = pcap_names_text
        row["pcap_files"] = pcap_names
        row["pcapFiles"] = pcap_names
        row["pcap_file_names"] = pcap_names
        row["pcap_names_list"] = pcap_names
        row["pcap_count"] = pcap_count
        row["pcapCount"] = pcap_count
        row["pcap_appearance_count"] = pcap_count
        row["pcapAppearanceCount"] = pcap_count

    return rows


def get_external_ips_for_pcap(pcap_id):
    es = get_es()
    if not es: return []
    source = get_pcap_ip_docs([pcap_id], es).get(pcap_id, {})
    return source.get("external_ips", [])


def get_internal_ips_for_pcap(pcap_id):
    source = get_pcap_ip_docs([pcap_id]).get(pcap_id, {})
    return source.get("internal_ips", [])


def get_dns_queries_for_pcap(pcap_id, limit=200):
    """Read domains from the embedded array in the single pcap-dns doc."""
    es = get_es()
    if not es: return []
    try:
        doc = es.get(index=PCAP_DNS_INDEX, id=pcap_id)["_source"]
        domains = [
            d for d in (doc.get("domains") or [])
            if d.get("type") == "dns"
        ]
        domains.sort(key=lambda d: d.get("count", 0), reverse=True)
        return [
            {"domain": d.get("domain"), "record_type": d.get("record_type"), "count": d.get("count")}
            for d in domains[:limit]
        ]
    except Exception:
        return []



def get_ip_geo_from_pcap_ips(ip):
    """Fetch geo fields for an IP directly from pcap-ips as a fast fallback."""
    es = get_es()
    if not es:
        return {}
    try:
        res = es.search(index=PCAP_IPS_INDEX, body={
            "query": {"nested": {
                "path": "ips",
                "query": {"term": {"ips.ip": ip}},
            }},
            "_source": ["ips"],
            "size": 1
        })
        hits = res.get("hits", {}).get("hits", [])
        if hits:
            for entry in hits[0].get("_source", {}).get("ips", []):
                if entry.get("ip") == ip:
                    return {
                        "country": entry.get("country"),
                        "city": entry.get("city"),
                        "isp": entry.get("isp"),
                        "latitude": entry.get("latitude"),
                        "longitude": entry.get("longitude"),
                    }
    except Exception:
        pass
    return {}


def get_ip_scan(ip):
    es = get_es()
    if not es: return None
    try:
        doc = es.get(index=IP_INTEL_INDEX, id=ip)
        return doc.get("_source")
    except NotFoundError:
        return None
    except Exception:
        return None


FEEDBACK_INDEX = "feedback"


def create_map_country_cache_index():
    es = get_es()
    if not es:
        return
    if not es.indices.exists(index=MAP_COUNTRY_CACHE_INDEX):
        es.indices.create(index=MAP_COUNTRY_CACHE_INDEX, body={
            "mappings": {
                "properties": {
                    "sinkhole_id": {"type": "integer"},
                    "name":       {"type": "keyword"},
                    "count":      {"type": "integer"},
                    "packets":    {"type": "long"},
                    "captures":   {"type": "integer"},
                    "latitude":   {"type": "double"},
                    "longitude":  {"type": "double"},
                    "updated_at": {"type": "date"},
                }
            }
        })
        print("Created Index: map-country-cache")


def refresh_map_country_cache(sinkhole_id=GLOBAL_DASHBOARD_SINKHOLE_ID):
    from helpers import scroll_country_aggregation
    es = get_es()
    if not es:
        return
    create_map_country_cache_index()
    try:
        pcap_ids = get_pcap_ids_for_sinkhole(sinkhole_id, es)
        country_data, country_packets, country_captures = scroll_country_aggregation(
            es, PCAP_IPS_INDEX, pcap_ids=pcap_ids
        )
        es.delete_by_query(
            index=MAP_COUNTRY_CACHE_INDEX,
            body={"query": {"match_all": {}}},
            refresh=True,
            conflicts="proceed",
        )
        if not country_data:
            return
        # Keep map coordinates in the same sinkhole scope as its counts.
        country_coords = {}
        try:
            res = es.search(index=PCAP_IPS_INDEX, body={
                "query": {"terms": {"pcap_id": pcap_ids}},
                "size": 0,
                "aggs": {"external": {"nested": {"path": "ips"}, "aggs": {
                    "external_only": {"filter": {"term": {"ips.is_internal": False}}, "aggs": {
                    "countries": {"terms": {"field": "ips.country", "size": 10000}, "aggs": {
                        "avg_lat": {"avg": {"field": "ips.latitude"}},
                        "avg_lon": {"avg": {"field": "ips.longitude"}},
                    }}
                    }}
                }}}
            })
            buckets = (res.get("aggregations", {}).get("external", {})
                       .get("external_only", {}).get("countries", {}).get("buckets", []))
            for b in buckets:
                country_coords[b["key"]] = {
                    "latitude":  b["avg_lat"].get("value"),
                    "longitude": b["avg_lon"].get("value"),
                }
        except Exception as e:
            print(f"refresh_map_country_cache coords error: {e}")
        now = datetime.now(timezone.utc).isoformat()
        bulk_body = []
        for country, count in country_data.items():
            coords = country_coords.get(country, {})
            bulk_body.append({"index": {"_index": MAP_COUNTRY_CACHE_INDEX, "_id": country}})
            bulk_body.append({
                "sinkhole_id": sinkhole_id,
                "name":       country,
                "count":      count,
                "packets":    country_packets[country],
                "captures":   len(country_captures[country]),
                "latitude":   coords.get("latitude"),
                "longitude":  coords.get("longitude"),
                "updated_at": now,
            })
        if bulk_body:
            es.bulk(body=bulk_body, refresh=True)
            print(f"map-country-cache refreshed: {len(country_data)} countries")
    except Exception as e:
        print(f"refresh_map_country_cache error: {e}")


def get_map_country_cache(sinkhole_id=GLOBAL_DASHBOARD_SINKHOLE_ID):
    """Read the materialized view. Returns list sorted by count desc."""
    es = get_es()
    if not es:
        return []
    try:
        res = es.search(index=MAP_COUNTRY_CACHE_INDEX, body={
            "query": {"term": {"sinkhole_id": sinkhole_id}},
            "size": 10000,
            "sort": [{"count": {"order": "desc"}}],
            "_source": ["name", "count", "packets", "captures", "latitude", "longitude"],
        })
        return [h["_source"] for h in res["hits"]["hits"]]
    except Exception:
        return []


def create_geo_breakdown_cache_index():
    es = get_es()
    if not es:
        return
    if not es.indices.exists(index=GEO_BREAKDOWN_CACHE_INDEX):
        es.indices.create(index=GEO_BREAKDOWN_CACHE_INDEX, body={
            "mappings": {"properties": {
                "type":        {"type": "keyword"},
                "name":        {"type": "keyword"},
                "packets":     {"type": "long"},
                "connections": {"type": "long"},
                "updated_at":  {"type": "date"},
            }}
        })
        print("Created Index: geo-breakdown-cache")


def refresh_geo_breakdown_cache():
    """No-op: geo breakdown now reads directly from ip-intelligence via terms aggregations."""
    pass


def get_geo_breakdown_cache():
    """Read geo breakdown directly from ip-intelligence via terms aggregations."""
    es = get_es()
    if not es:
        return None
    try:
        res = es.search(index=IP_INTEL_INDEX, body={"size": 0, "aggs": {
            "countries": {"terms": {"field": "geo.country.keyword", "size": 10000}},
            "cities":    {"terms": {"field": "geo.city.keyword",    "size": 10000}},
            "isps":      {"terms": {"field": "geo.isp.keyword",     "size": 10000}},
        }})
        aggs = res.get("aggregations", {})
        def _to_list(agg_key):
            return [{"name": b["key"], "packets": 0, "connections": 0} for b in aggs.get(agg_key, {}).get("buckets", [])]
        result = {
            "countries": _to_list("countries"),
            "cities":    _to_list("cities"),
            "isps":      _to_list("isps"),
        }
        return result if any(result.values()) else None
    except Exception:
        return None


def create_feedback_index():
    es = get_es()
    if not es:
        return
    if es.indices.exists(index=FEEDBACK_INDEX):
        return
    es.indices.create(index=FEEDBACK_INDEX, body={
        "mappings": {
            "properties": {
                "name":         {"type": "keyword"},
                "email":        {"type": "keyword"},
                "organisation": {"type": "keyword"},
                "message":      {"type": "text"},
                "role":         {"type": "keyword"},
                "submitted_at": {"type": "date"},
            }
        }
    })
    print("\u2713 Created Index: feedback")


def index_feedback(name, email, organisation, message, role="user"):
    es = get_es()
    if not es:
        return None
    create_feedback_index()
    doc = {
        "name":         name,
        "email":        email,
        "organisation": organisation,
        "message":      message,
        "role":         role,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    return es.index(index=FEEDBACK_INDEX, document=doc)



def _recent_log_total(es, pcap_id):
    if pcap_id:
        meta = es.get(index=PCAP_METADATA_INDEX, id=pcap_id)["_source"]
        return int(meta.get("total_connections", 0) or 0)

    res = es.search(
        index=PCAP_METADATA_INDEX,
        body={"query": {"match_all": {}}, "size": 0, "aggs": {"total": {"sum": {"field": "total_connections"}}}},
    )
    return int(res.get("aggregations", {}).get("total", {}).get("value", 0) or 0)


_CONN_STATE_MAP = {
    'S0': 'SYN sent, no response received',
    'S1': 'Connection established, not closed',
    'SF': 'Normal connection setup and proper closure',
    'REJ': 'Connection attempt rejected',
    'S2': 'Connection established, initiator tried to close, no responder reply',
    'S3': 'Connection established, responder tried to close, no initiator reply',
    'RSTO': 'Initiator reset (aborted) the connection',
    'RSTR': 'Responder reset the connection',
    'RSTOS0': 'Initiator sent SYN then RST, no SYN-ACK seen',
    'RSTRH': 'Responder sent SYN-ACK then RST, no SYN from initiator seen',
    'SH': 'Initiator sent SYN then FIN, connection half-open',
    'SHR': 'Responder sent SYN-ACK then FIN, no SYN from initiator',
    'OTH': 'Midstream traffic only, no SYN observed',
}


def _format_recent_log(log):
    formatted = {}
    for key, value in log.items():
        if key == 'ts':
            # ts is now an ISO string (e.g. "2023-12-07T15:11:56.804497+00:00")
            try:
                formatted['timestamp'] = datetime.fromisoformat(str(value)).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                try:
                    formatted['timestamp'] = datetime.fromtimestamp(float(value), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    formatted['timestamp'] = value
        elif key in ('id.orig_h', 'orig_h'):
            formatted['src_ip'] = value
        elif key in ('id.resp_h', 'resp_h'):
            formatted['dest_ip'] = value
        elif key in ('id.resp_p', 'resp_p'):
            formatted['resp_port'] = value
        elif key == 'conn_state':
            formatted['conn_state'] = value
            formatted['conn_state_desc'] = _CONN_STATE_MAP.get(str(value).upper(), value)
        elif key == 'duration':
            try:
                formatted[key] = f"{float(value):.6f}"
            except (ValueError, TypeError):
                formatted[key] = value
        else:
            formatted[key] = value
    return formatted


def _load_recent_logs_from_zeek_conn(es, pcap_id, start, per_page):
    if pcap_id:
        doc = es.get(index="zeek-conn", id=pcap_id)["_source"]
        all_conns = doc.get("connections", [])
    else:
        res = es.search(index="zeek-conn", body={"query": {"match_all": {}}, "size": 1000, "_source": ["connections"]})
        all_conns = []
        for hit in res["hits"]["hits"]:
            all_conns.extend(hit["_source"].get("connections") or [])
        all_conns.sort(key=lambda row: str(row.get("ts") or ""), reverse=True)

    return [_format_recent_log(row) for row in all_conns[start:start + per_page]]


def get_sf_connection_counts_for_pcap(pcap_id):
    """Return {ip: sf_count} using ES scripted_metric aggregation for a specific pcap."""
    es = get_es()
    if not es:
        return {}
    try:
        res = es.search(index=ZEEK_CONN_INDEX, body={
            "size": 0,
            "query": {"ids": {"values": [pcap_id]}},
            "aggs": {"sf_per_ip": {"scripted_metric": {
                "init_script": "state.map = [:]",
                "map_script": """
                    if (params._source.connections != null) {
                        for (c in params._source.connections) {
                            if (c.conn_state == 'SF') {
                                for (def f : ['id.orig_h', 'id.resp_h']) {
                                    def ip = c[f];
                                    if (ip != null) {
                                        def k = ip.toString();
                                        state.map[k] = (state.map.containsKey(k) ? state.map[k] : 0) + 1;
                                    }
                                }
                            }
                        }
                    }
                """,
                "combine_script": "return state.map",
                "reduce_script": "def out = [:]; for (s in states) { if (s != null) { for (e in s.entrySet()) { out[e.getKey()] = (out.containsKey(e.getKey()) ? out[e.getKey()] : 0) + e.getValue(); } } } return out"
            }}}
        })
        return res.get("aggregations", {}).get("sf_per_ip", {}).get("value") or {}
    except Exception:
        return {}


def get_recent_logs_from_es(pcap_id=None, per_page=50, page=1):
    """Paginate connections from zeek-conn embedded array in Elasticsearch."""
    es = get_es()
    if not es:
        return {"logs": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

    start = (page - 1) * per_page

    try:
        total = _recent_log_total(es, pcap_id)
    except Exception:
        total = 0

    total_pages = math.ceil(total / per_page) if per_page > 0 else 0
    logs = _load_recent_logs_from_zeek_conn(es, pcap_id, start, per_page)
    return {"logs": logs, "total": total, "page": page, "per_page": per_page, "total_pages": total_pages}


def get_pcap_files(pcap_id):
    """Fetch files from the single pcap-files doc for this pcap_id."""
    es = get_es()
    if not es:
        return []
    try:
        doc = es.get(index=PCAP_FILES_INDEX, id=pcap_id)
        return doc["_source"].get("files", [])
    except Exception:
        return []


def get_dns_requests(pcap_id=None, page=1, per_page=50, search="", pcap_ids=None):
    """Return URL request records from dns-requests.

    Each record includes url, host, uri, connected_ip_count, request_count,
    total_connections, and connected_ips[{ip, isp, latitude, longitude}].
    total_connections is the summed request_count for that domain. Optionally
    scoped to a pcap_id and/or filtered by a url/host substring. Sorted by
    connected IP count (desc), then request count (desc).

    When no pcap_id is given, the same URL can exist as separate per-pcap
    documents. Those are merged into a single row per URL: connected IPs are
    unioned (deduped by ip), request counts summed, and connected_ip_count
    recomputed from the merged IP set.
    """
    es = get_es()
    if not es:
        return {"requests": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

    must = []
    if pcap_id:
        must.append({"term": {"pcap_id": pcap_id}})
    elif pcap_ids is not None:
        must.append({"terms": {"pcap_id": pcap_ids}})
    if search:
        must.append({"wildcard": {"url": {"value": f"*{search.lower()}*", "case_insensitive": True}}})
    # Exclude raw IPv4-literal hosts -- these are direct-to-IP requests, not domains.
    must_not = [{"regexp": {"host": "[0-9]{1,3}(\\.[0-9]{1,3}){3}"}}]
    query = {"bool": {"must": must, "must_not": must_not}}

    per_page = max(1, min(per_page, 200))

    # Per-pcap: URLs are already unique within a pcap, so paginate in ES.
    if pcap_id:
        start = (page - 1) * per_page
        try:
            res = es.search(
                index=DNS_REQUESTS_INDEX,
                body={
                    "query": query,
                    "from": start,
                    "size": per_page,
                    "sort": [
                        {"connected_ip_count": {"order": "desc"}},
                        {"request_count": {"order": "desc"}},
                    ],
                },
            )
        except Exception as e:
            print(f"get_dns_requests error: {e}")
            return {"requests": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

        hits = res["hits"]["hits"]
        total = res["hits"]["total"]
        total = total["value"] if isinstance(total, dict) else total
        total_pages = math.ceil(total / per_page) if per_page > 0 else 0

        requests = [{
            "url": h["_source"].get("url"),
            "host": h["_source"].get("host"),
            "uri": h["_source"].get("uri"),
            "connected_ip_count": h["_source"].get("connected_ip_count", 0),
            "request_count": h["_source"].get("request_count", 0),
            "total_connections": h["_source"].get("request_count", 0),
            "connected_ips": h["_source"].get("connected_ips", []),
            "pcap_id": h["_source"].get("pcap_id"),
        } for h in hits]

        return {"requests": requests, "total": total, "page": page, "per_page": per_page, "total_pages": total_pages}

    # Global: merge by URL across pcaps using ES aggregations (server-side).
    # A scripted_metric per host bucket dedupes connected IPs (keeping their
    # isp/lat/lon), sums request counts and collects the source pcaps.
    merge_metric = {
        "scripted_metric": {
            "init_script": "state.ips = [:]; state.reqs = 0L; state.pcaps = new HashSet();",
            "map_script": """
                state.reqs += (doc.containsKey('request_count') && doc['request_count'].size() > 0)
                    ? doc['request_count'].value : 0;
                if (doc.containsKey('pcap_id') && doc['pcap_id'].size() > 0) {
                    state.pcaps.add(doc['pcap_id'].value);
                }
                if (params._source.connected_ips != null) {
                    for (c in params._source.connected_ips) {
                        if (c.ip != null && !state.ips.containsKey(c.ip)) {
                            state.ips[c.ip] = ['ip': c.ip, 'isp': c.isp,
                                               'latitude': c.latitude, 'longitude': c.longitude];
                        }
                    }
                }
            """,
            "combine_script": "return ['ips': state.ips, 'reqs': state.reqs, 'pcaps': new ArrayList(state.pcaps)];",
            "reduce_script": """
                Map ips = [:]; long reqs = 0; Set pcaps = new HashSet();
                for (s in states) {
                    reqs += s.reqs;
                    for (p in s.pcaps) { pcaps.add(p); }
                    for (e in s.ips.entrySet()) { if (!ips.containsKey(e.getKey())) { ips[e.getKey()] = e.getValue(); } }
                }
                return ['ips': new ArrayList(ips.values()), 'reqs': reqs,
                        'ip_count': ips.size(), 'pcaps': new ArrayList(pcaps)];
            """,
        }
    }

    try:
        # Count distinct hosts for pagination metadata.
        card = es.search(
            index=DNS_REQUESTS_INDEX,
            body={"query": query, "size": 0,
                  "aggs": {"host_count": {"cardinality": {"field": "host"}}}},
        )
        total = int(card["aggregations"]["host_count"]["value"])

        # Return one bucket per host (merging across differing URIs), ordered by
        # unique IP count, sized to cover the requested page.
        bucket_limit = page * per_page
        res = es.search(
            index=DNS_REQUESTS_INDEX,
            body={
                "query": query,
                "size": 0,
                "aggs": {
                    "by_host": {
                        "terms": {
                            "field": "host",
                            "size": max(bucket_limit, 1),
                            "order": {"ip_count": "desc"},
                        },
                        "aggs": {
                            "merged": merge_metric,
                            "ip_count": {"cardinality": {"field": "connected_ips.ip"}},
                        },
                    }
                },
            },
        )
    except Exception as e:
        print(f"get_dns_requests error: {e}")
        return {"requests": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

    buckets = res["aggregations"]["by_host"]["buckets"]
    requests = []
    for b in buckets:
        merged = b["merged"]["value"] or {}
        connected_ips = merged.get("ips", [])
        requests.append({
            "host": b["key"],
            "url": b["key"],
            "connected_ip_count": int(merged.get("ip_count", len(connected_ips)) or 0),
            "request_count": int(merged.get("reqs", 0) or 0),
            "total_connections": int(merged.get("reqs", 0) or 0),
            "connected_ips": connected_ips,
            "pcap_ids": sorted(merged.get("pcaps", []) or []),
        })

    # Buckets are already ordered by unique IP count; take the requested page.
    total_pages = math.ceil(total / per_page) if per_page > 0 else 0
    start = (page - 1) * per_page
    page_slice = requests[start:start + per_page]

    return {"requests": page_slice, "total": total, "page": page, "per_page": per_page, "total_pages": total_pages}


def get_dns_requests_for_sinkhole(sinkhole_id, page=1, per_page=50, search=""):
    """Return DNS request records aggregated across a sinkhole set's PCAPs."""
    pcap_ids = get_pcap_ids_for_sinkhole(sinkhole_id)
    if not pcap_ids:
        return {
            "requests": [],
            "total": 0,
            "page": page,
            "per_page": per_page,
            "total_pages": 0,
        }
    return get_dns_requests(
        page=page,
        per_page=per_page,
        search=search,
        pcap_ids=pcap_ids,
    )


def get_dns_sinkhole_domain_details(sinkhole_id, domain):
    """Return connected-IP activity and domain totals for one domain."""
    es = get_es()
    if not es:
        raise RuntimeError("Elasticsearch is unavailable")

    pcap_ids = get_pcap_ids_for_sinkhole(sinkhole_id, es)
    if not pcap_ids:
        return {"host": domain, "request_count": 0, "timeline": [], "ips": []}

    response = es.search(
        index=DNS_REQUESTS_INDEX,
        body={
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"host": domain}},
                        {"terms": {"pcap_id": pcap_ids}},
                    ],
                },
            },
            "_source": [
                "request_count",
                "pcap_id",
                "connected_ips",
            ],
            "size": 500,
        },
        scroll="2m",
    )
    scroll_id = response.get("_scroll_id")
    total_requests = 0
    request_records = []
    timeline = {}
    ip_details = {}

    try:
        hits = response.get("hits", {}).get("hits", [])
        while hits:
            for hit in hits:
                source = hit.get("_source", {})
                request_count = int(source.get("request_count", 0) or 0)
                total_requests += request_count
                request_timestamps = set()
                pcap_id = source.get("pcap_id")
                for connected_ip in source.get("connected_ips") or []:
                    ip = connected_ip.get("ip")
                    if not ip:
                        continue

                    timestamp = connected_ip.get("timestamp")
                    if timestamp:
                        try:
                            parsed_timestamp = datetime.fromisoformat(
                                str(timestamp).replace("Z", "+00:00")
                            )
                            if parsed_timestamp.tzinfo is None:
                                parsed_timestamp = parsed_timestamp.replace(
                                    tzinfo=timezone.utc
                                )
                            timestamp = parsed_timestamp.astimezone(
                                timezone.utc
                            ).isoformat().replace("+00:00", "Z")
                        except (TypeError, ValueError):
                            timestamp = None

                    item = ip_details.setdefault(
                        ip,
                        {
                            "ip": ip,
                            "isp": connected_ip.get("isp") or "Unknown",
                            "country": connected_ip.get("country"),
                            "city": connected_ip.get("city"),
                            "latitude": connected_ip.get("latitude"),
                            "longitude": connected_ip.get("longitude"),
                            "first_seen": None,
                            "last_seen": None,
                            "timestamps": set(),
                            "url_record_count": 0,
                            "pcap_ids": set(),
                        },
                    )
                    item["url_record_count"] += 1
                    if pcap_id:
                        item["pcap_ids"].add(pcap_id)
                    if timestamp:
                        request_timestamps.add(timestamp)
                        item["timestamps"].add(timestamp)
                        point = timeline.setdefault(
                            timestamp,
                            {
                                "timestamp": timestamp,
                                "ips": set(),
                                "pcap_ids": set(),
                            },
                        )
                        point["ips"].add(ip)
                        if pcap_id:
                            point["pcap_ids"].add(pcap_id)
                        if (
                            not item["first_seen"]
                            or timestamp < item["first_seen"]
                        ):
                            item["first_seen"] = timestamp
                        if (
                            not item["last_seen"]
                            or timestamp > item["last_seen"]
                        ):
                            item["last_seen"] = timestamp

                request_records.append(
                    {
                        "request_count": request_count,
                        "timestamps": sorted(request_timestamps),
                    }
                )

            response = es.scroll(scroll_id=scroll_id, scroll="2m")
            scroll_id = response.get("_scroll_id", scroll_id)
            hits = response.get("hits", {}).get("hits", [])
    finally:
        if scroll_id:
            es.clear_scroll(scroll_id=scroll_id)

    timeline_rows = [
        {
            **point,
            "ip_count": len(point["ips"]),
            "ips": sorted(point["ips"]),
            "pcap_ids": sorted(point["pcap_ids"]),
        }
        for point in timeline.values()
    ]
    timeline_rows.sort(key=lambda point: point["timestamp"])

    domain_ips = list(ip_details)
    if domain_ips:
        geo_response = es.search(
            index=PCAP_IPS_INDEX,
            body={
                "query": {
                    "bool": {
                        "filter": [
                            {"terms": {"pcap_id": pcap_ids}},
                            {
                                "nested": {
                                    "path": "ips",
                                    "query": {
                                        "terms": {"ips.ip": domain_ips}
                                    },
                                }
                            },
                        ],
                    }
                },
                "_source": [
                    "pcap_id",
                    "ips.ip",
                    "ips.country",
                    "ips.city",
                    "ips.latitude",
                    "ips.longitude",
                ],
                "size": 500,
            },
            scroll="2m",
        )
        geo_scroll_id = geo_response.get("_scroll_id")
        try:
            geo_hits = geo_response.get("hits", {}).get("hits", [])
            while geo_hits:
                for hit in geo_hits:
                    for metadata in hit.get("_source", {}).get("ips") or []:
                        ip = metadata.get("ip")
                        if ip not in ip_details:
                            continue
                        item = ip_details[ip]
                        for field in ("country", "city", "latitude", "longitude"):
                            value = metadata.get(field)
                            if item.get(field) is None and value is not None:
                                if field == "country":
                                    value = str(value).strip()
                                    value = _COUNTRY_ALIASES.get(
                                        value.casefold(),
                                        value.upper() if len(value) == 2 else value,
                                    )
                                item[field] = value
                geo_response = es.scroll(scroll_id=geo_scroll_id, scroll="2m")
                geo_scroll_id = geo_response.get("_scroll_id", geo_scroll_id)
                geo_hits = geo_response.get("hits", {}).get("hits", [])
        finally:
            if geo_scroll_id:
                es.clear_scroll(scroll_id=geo_scroll_id)

        host_response = es.search(
            index=DNS_REQUESTS_INDEX,
            body={
                "query": {
                    "bool": {
                        "filter": [
                            {"terms": {"pcap_id": pcap_ids}},
                            {"terms": {"connected_ips.ip": domain_ips}},
                        ],
                    }
                },
                "_source": ["host", "connected_ips.ip"],
                "size": 500,
            },
            scroll="2m",
        )
        host_scroll_id = host_response.get("_scroll_id")
        hosts_by_ip = {ip: set() for ip in domain_ips}
        try:
            host_hits = host_response.get("hits", {}).get("hits", [])
            while host_hits:
                for hit in host_hits:
                    source = hit.get("_source", {})
                    host = source.get("host")
                    if not host:
                        continue
                    normalized_host = str(host).strip().rstrip(".").casefold()
                    if not normalized_host:
                        continue
                    for connected_ip in source.get("connected_ips") or []:
                        ip = connected_ip.get("ip")
                        if ip in hosts_by_ip:
                            hosts_by_ip[ip].add(normalized_host)
                host_response = es.scroll(scroll_id=host_scroll_id, scroll="2m")
                host_scroll_id = host_response.get("_scroll_id", host_scroll_id)
                host_hits = host_response.get("hits", {}).get("hits", [])
        finally:
            if host_scroll_id:
                es.clear_scroll(scroll_id=host_scroll_id)

    ips = [
        {
            **item,
            "domain_count": len(hosts_by_ip.get(item["ip"], set())),
            "domains": sorted(hosts_by_ip.get(item["ip"], set())),
            "pcap_ids": sorted(item["pcap_ids"]),
            "timestamps": sorted(item["timestamps"]),
        }
        for item in ip_details.values()
    ]
    ips.sort(key=lambda item: (-item["domain_count"], item["ip"]))

    return {
        "host": domain,
        "request_count": total_requests,
        "request_records": request_records,
        "timeline": timeline_rows,
        "ips": ips,
    }


def get_dns_sinkhole_summary(sinkhole_id):
    """Return DNS request totals and top domain, country, and ISP stats."""
    es = get_es()
    if not es:
        raise RuntimeError("Elasticsearch is unavailable")

    pcap_count = int(es.count(
        index=PCAP_METADATA_INDEX,
        body={"query": {"term": {"sinkhole_id": sinkhole_id}}},
    ).get("count", 0))
    pcap_ids = get_pcap_ids_for_sinkhole(sinkhole_id, es)
    if pcap_count and not pcap_ids:
        raise RuntimeError(f"Could not retrieve PCAP IDs for sinkhole set {sinkhole_id}")

    summary = {
        "domain_count": 0,
        "pcap_count": pcap_count,
        "request_count": 0,
        "external_ip_count": 0,
        "internal_ip_count": 0,
        "external_ips": [],
        "top_active_domains": [],
        "top_countries": [],
        "top_isps": [],
    }
    if not pcap_ids:
        return summary

    def iter_source_docs(index, source_fields, query):
        response = es.search(
            index=index,
            body={"query": query, "_source": source_fields, "size": 500},
            scroll="2m",
        )
        scroll_id = response.get("_scroll_id")
        try:
            hits = response.get("hits", {}).get("hits", [])
            while hits:
                for hit in hits:
                    yield hit.get("_source", {})
                response = es.scroll(scroll_id=scroll_id, scroll="2m")
                scroll_id = response.get("_scroll_id", scroll_id)
                hits = response.get("hits", {}).get("hits", [])
        finally:
            if scroll_id:
                es.clear_scroll(scroll_id=scroll_id)

    pcap_query = {"terms": {"pcap_id": pcap_ids}}
    ip_metadata_by_pcap_ip = {}
    external_ips = set()
    external_ip_records = {}
    internal_ips = set()
    for source in iter_source_docs(
        PCAP_IPS_INDEX,
        [
            "pcap_id",
            "ips.ip",
            "ips.is_internal",
            "ips.country",
            "ips.city",
            "ips.isp",
            "ips.latitude",
            "ips.longitude",
        ],
        pcap_query,
    ):
        pcap_id = source.get("pcap_id")
        for item in source.get("ips") or []:
            ip = item.get("ip")
            if not ip:
                continue
            country = item.get("country")
            if country:
                country = str(country).strip()
                country = _COUNTRY_ALIASES.get(
                    country.casefold(),
                    country.upper() if len(country) == 2 else country,
                )
            if item.get("is_internal") is True:
                internal_ips.add(ip)
            elif item.get("is_internal") is False:
                external_ips.add(ip)
                ip_details = external_ip_records.setdefault(
                    ip,
                    {
                        "ip": ip,
                        "country": country,
                        "city": None,
                        "isp": None,
                        "latitude": None,
                        "longitude": None,
                    },
                )
                for field in ("country", "city", "isp", "latitude", "longitude"):
                    if ip_details[field] is None and item.get(field) is not None:
                        ip_details[field] = item[field]
            else:
                continue
            if pcap_id:
                ip_metadata_by_pcap_ip[(pcap_id, ip)] = {
                    "country": country,
                    "latitude": item.get("latitude"),
                    "longitude": item.get("longitude"),
                }

    summary["external_ip_count"] = len(external_ips)
    summary["internal_ip_count"] = len(internal_ips)
    summary["external_ips"] = [
        external_ip_records[ip] for ip in sorted(external_ip_records)
    ]

    domain_requests = {}
    domains = set()
    country_domains = {}
    isp_ips = {}
    isp_requests = {}
    dns_query = {
        "bool": {
            "filter": [pcap_query],
            "must_not": [{"regexp": {"host": "[0-9]{1,3}(\\.[0-9]{1,3}){3}"}}],
        }
    }
    for source in iter_source_docs(
        DNS_REQUESTS_INDEX,
        ["pcap_id", "host", "request_count", "connected_ips"],
        dns_query,
    ):
        host = source.get("host")
        if not host:
            continue
        request_count = int(source.get("request_count", 0) or 0)
        domains.add(host)
        domain_requests[host] = domain_requests.get(host, 0) + request_count
        summary["request_count"] += request_count

        pcap_id = source.get("pcap_id")
        record_isps = set()
        for connected_ip in source.get("connected_ips") or []:
            ip = connected_ip.get("ip")
            isp = connected_ip.get("isp")
            if ip and isp:
                metadata = ip_metadata_by_pcap_ip.get((pcap_id, ip), {})
                country = metadata.get("country") or connected_ip.get("country")
                if country:
                    country = str(country).strip()
                    country = _COUNTRY_ALIASES.get(
                        country.casefold(),
                        country.upper() if len(country) == 2 else country,
                    )
                ip_details = isp_ips.setdefault(isp, {}).setdefault(
                    ip,
                    {
                        "ip": ip,
                        "latitude": None,
                        "longitude": None,
                        "country": None,
                    },
                )
                for field in ("latitude", "longitude"):
                    if ip_details[field] is None:
                        ip_details[field] = (
                            metadata.get(field)
                            if metadata.get(field) is not None
                            else connected_ip.get(field)
                        )
                if ip_details["country"] is None:
                    ip_details["country"] = country
                record_isps.add(isp)
            else:
                metadata = ip_metadata_by_pcap_ip.get((pcap_id, ip), {})
            country = metadata.get("country") or connected_ip.get("country")
            if country:
                country = str(country).strip()
                country = _COUNTRY_ALIASES.get(
                    country.casefold(),
                    country.upper() if len(country) == 2 else country,
                )
                country_domains.setdefault(country, set()).add(host)

        for isp in record_isps:
            isp_requests[isp] = isp_requests.get(isp, 0) + request_count

    summary["domain_count"] = len(domains)
    summary["top_active_domains"] = [
        {"host": host, "request_count": request_count}
        for host, request_count in sorted(
            domain_requests.items(), key=lambda item: (-item[1], item[0])
        )[:10]
    ]
    summary["top_countries"] = [
        {
            "country": country,
            "domain_count": len(hosts),
            "domains": sorted(hosts),
        }
        for country, hosts in sorted(
            country_domains.items(), key=lambda item: (-len(item[1]), item[0])
        )[:10]
    ]
    summary["top_isps"] = [
        {
            "isp": isp,
            "ip_count": len(ips),
            "request_count": isp_requests.get(isp, 0),
            "ips": [ips[ip] for ip in sorted(ips)],
        }
        for isp, ips in sorted(
            isp_ips.items(),
            key=lambda item: (
                -isp_requests.get(item[0], 0),
                -len(item[1]),
                item[0],
            ),
        )[:10]
    ]
    return summary


def get_all_pcap_list(search="", page=1, per_page=12):
    """Get PCAPs from pcap-metadata with ES-side pagination."""
    es = get_es()
    if not es:
        return [], 0
    try:
        query = {"match_all": {}}
        if search:
            query = {"wildcard": {"pcap_filename": {"value": f"*{search}*", "case_insensitive": True}}}

        # Get total count
        count_res = es.count(index=PCAP_METADATA_INDEX, body={"query": query})
        total = count_res.get("count", 0)

        # Fetch only the page we need
        start = (page - 1) * per_page
        res = es.search(
            index=PCAP_METADATA_INDEX,
            body={
                "query": query,
                "_source": ["pcap_id", "pcap_filename", "file_name", "file_size", "summary", "total_packets", "duration_seconds", "unique_ips"],
                "sort": [{"analysis_timestamp": {"order": "desc", "unmapped_type": "date"}}],
                "from": start,
                "size": per_page,
            }
        )
        results = []
        for hit in res["hits"]["hits"]:
            src = hit["_source"]
            filename = src.get("pcap_filename", src.get("file_name", ""))
            results.append({
                "pcap_id": src.get("pcap_id"),
                "filename": filename,
                "size": src.get("file_size") or src.get("summary", {}).get("file_size", 0),
                "packets": src.get("total_packets"),
                "duration": src.get("duration_seconds"),
                "ip_count": src.get("unique_ips", 0)
            })
        return results, total
    except Exception:
        return [], 0


def get_time_series(pcap_id=None):
    """Return pre-aggregated time_series from PCAP metadata or Zeek records."""
    es = get_es()
    if not es:
        return []

    def merge_time_series(hits):
        from collections import defaultdict
        merged = defaultdict(int)
        for hit in hits:
            for point in hit.get("_source", {}).get("time_series") or []:
                label = point.get("label")
                value = point.get("value")
                if label is not None and value is not None:
                    merged[label] += value
        return [{"label": label, "value": value} for label, value in sorted(merged.items())]

    def build_series_from_connections(hits):
        from collections import defaultdict
        counts = defaultdict(int)
        for hit in hits:
            source = hit.get("_source", {})
            connections = source.get("connections")
            if isinstance(connections, list):
                rows = connections
            else:
                rows = [source]
            for row in rows:
                raw_ts = row.get("ts") or row.get("timestamp")
                if raw_ts is None:
                    continue
                try:
                    if isinstance(raw_ts, (int, float)):
                        timestamp = datetime.fromtimestamp(raw_ts, timezone.utc)
                    else:
                        timestamp = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
                        if timestamp.tzinfo is None:
                            timestamp = timestamp.replace(tzinfo=timezone.utc)
                    label = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                except (ValueError, TypeError, OverflowError, OSError):
                    continue
                counts[label] += 1
        return [{"label": label, "value": value} for label, value in sorted(counts.items())]

    def search_pcap_zeek_records(target_pcap_id):
        query = {"term": {"pcap_id": target_pcap_id}}
        response = es.search(index=ZEEK_CONN_INDEX, body={
            "query": query,
            "size": 1000,
            "_source": ["time_series", "connections", "ts", "timestamp", "pcap_id"],
        }, scroll="2m")
        hits = []
        scroll_id = response.get("_scroll_id")
        try:
            while True:
                page_hits = response.get("hits", {}).get("hits", [])
                if not page_hits:
                    break
                hits.extend(page_hits)
                if not scroll_id:
                    break
                response = es.scroll(scroll_id=scroll_id, scroll="2m")
                scroll_id = response.get("_scroll_id", scroll_id)
        finally:
            if scroll_id:
                es.clear_scroll(scroll_id=scroll_id)
        return hits

    try:
        if pcap_id:
            query = {"bool": {"should": [
                {"term": {"pcap_id": pcap_id}},
                {"term": {"file_id": pcap_id}},
            ], "minimum_should_match": 1}}
            metadata = es.search(index=PCAP_METADATA_INDEX, body={
                "query": query,
                "size": 1000,
                "_source": ["time_series"],
            })
            data = merge_time_series(metadata.get("hits", {}).get("hits", []))
            if data:
                return data

            # Generate the series from Zeek connection timestamps when no summary was stored.
            zeek_hits = search_pcap_zeek_records(pcap_id)
            data = merge_time_series(zeek_hits)
            if data:
                return data
            data = build_series_from_connections(zeek_hits)
            if data:
                return data

            # Older deployments may use the PCAP ID as the Zeek document ID.
            try:
                legacy = es.get(index=ZEEK_CONN_INDEX, id=pcap_id)
                legacy_hits = [{"_source": legacy.get("_source", {})}]
                return merge_time_series(legacy_hits) or build_series_from_connections(legacy_hits)
            except NotFoundError:
                return []

        # Global: prefer dashboard metadata, retaining compatibility with older Zeek documents.
        metadata = es.search(index=PCAP_METADATA_INDEX, body={
            "query": {"match_all": {}},
            "size": 10000,
            "_source": ["time_series"],
        })
        data = merge_time_series(metadata.get("hits", {}).get("hits", []))
        if data:
            return data

        zeek = es.search(index=ZEEK_CONN_INDEX, body={
            "query": {"match_all": {}},
            "size": 10000,
            "_source": ["time_series", "connections", "ts", "timestamp", "pcap_id"],
        })
        zeek_hits = zeek.get("hits", {}).get("hits", [])
        return merge_time_series(zeek_hits) or build_series_from_connections(zeek_hits)
    except Exception as e:
        print(f"time_series error: {e}")
        return []


def get_geo_aggregation(pcap_id=None):
    """Aggregate ISP/Country/City with packets and connections."""
    try:
        return get_ip_breakdown(pcap_id)
    except Exception as e:
        print(f"get_geo_aggregation error: {e}")
        return {"countries": [], "isps": [], "cities": []}


def _metric_map(agg):
    if not isinstance(agg, dict):
        return {}
    value = agg.get("value")
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return {str(v): 1 for v in value}
    if isinstance(agg.get("map"), dict):
        return agg.get("map")
    return {}


def _to_items(values, label_key="label"):
    return [{label_key: k, "value": int(v)} for k, v in sorted((values or {}).items(), key=lambda x: x[1], reverse=True)]


def _apply_metadata_aggs(es, stats, sinkhole_id=None):
    """Run pcap-metadata aggregation and update stats in-place."""
    res = es.search(index=PCAP_METADATA_INDEX, body={
        "query": {"match_all": {}} if sinkhole_id is None else {"term": {"sinkhole_id": sinkhole_id}},
        "size": 0,
        "aggs": {
            "total_bytes":       {"sum": {"field": "total_bytes"}},
            "total_packets":     {"sum": {"field": "total_packets"}},
            "total_connections": {"sum": {"field": "total_connections"}},
            "total_file_size":   {"sum": {"field": "file_size"}},
            "total_duration":    {"sum": {"field": "duration_seconds"}},
            "transport_breakdown": {
                "terms": {"field": "transport_breakdown.label", "size": 100},
                "aggs": {"total": {"sum": {"field": "transport_breakdown.value"}}}
            },
            "application_breakdown": {
                "terms": {"field": "application_breakdown.label", "size": 100},
                "aggs": {"total": {"sum": {"field": "application_breakdown.value"}}}
            },
            "direction_breakdown": {
                "terms": {"field": "direction_breakdown.label", "size": 100},
                "aggs": {"total": {"sum": {"field": "direction_breakdown.value"}}}
            },
            "top_dns_domains": {
                "terms": {"field": "top_dns_domains.label", "size": 1000},
                "aggs": {"total": {"sum": {"field": "top_dns_domains.value"}}}
            },
            "top_url_domains": {
                "terms": {"field": "top_url_domains.label", "size": 1000},
                "aggs": {"total": {"sum": {"field": "top_url_domains.value"}}}
            },
            "infected_hosts": {
                "terms": {
                    "field": "infected_host",
                    "size": 10000,
                    "exclude": ["Unknown", "N/A", "-", "None", "null", ""]
                }
            }
        }
    })
    aggs = res.get("aggregations", {})
    stats["total_bytes"]       = int(aggs.get("total_bytes", {}).get("value", 0) or 0)
    stats["total_packets"]     = int(aggs.get("total_packets", {}).get("value", 0) or 0)
    stats["total_connections"] = int(aggs.get("total_connections", {}).get("value", 0) or 0)
    stats["total_file_size"]   = int(aggs.get("total_file_size", {}).get("value", 0) or 0)
    stats["total_duration"]    = float(aggs.get("total_duration", {}).get("value", 0) or 0.0)

    def _nested_to_dict(agg_key):
        buckets = aggs.get(agg_key, {}).get("buckets", [])
        return {b["key"]: int(b["total"]["value"] or 0) for b in buckets}

    transport_vals    = {k: v for k, v in _nested_to_dict("transport_breakdown").items() if k.upper() not in {"UNKNOWN_TRANSPORT", "UNKNOWN"}}
    application_vals  = _nested_to_dict("application_breakdown")
    direction_vals    = _nested_to_dict("direction_breakdown")
    dns_vals          = _nested_to_dict("top_dns_domains")
    url_vals          = _nested_to_dict("top_url_domains")

    infected_buckets  = aggs.get("infected_hosts", {}).get("buckets", [])
    infected_vals     = sorted([
        b["key"] for b in infected_buckets
        if b["key"] and "::" not in b["key"]
        and not b["key"].startswith(("231.", "224.", "239."))
    ])

    stats["transport_breakdown"]   = _to_items(transport_vals)
    stats["application_breakdown"] = _to_items(application_vals)
    stats["direction_breakdown"]   = _to_items(direction_vals)
    stats["top_dns_domains"]       = _to_items(dns_vals)
    stats["top_url_domains"]       = _to_items(url_vals)
    stats["infected_hosts"]        = infected_vals
    stats["infected_hosts_count"]  = len(infected_vals)
    stats["total_infected_hosts"]  = len(infected_vals)
    stats["total_protocols"]       = len(transport_vals)
    stats["protocol_breakdown"]    = [{"protocol": k, "count": v} for k, v in sorted(transport_vals.items(), key=lambda x: x[1], reverse=True)[:10]]
    stats["total_dns_domains"]     = len(dns_vals)
    stats["total_url_domains"]     = len(url_vals)


def _apply_ip_aggs(es, stats, pcap_ids=None):
    """Run pcap-ips aggregation and update stats in-place. Exact counts via scripted_metric."""
    query = {"match_all": {}} if pcap_ids is None else {"terms": {"pcap_id": pcap_ids}} if pcap_ids else {"match_none": {}}
    # Keep scripted_metric only for exact unique IP counts
    res = es.search(index=PCAP_IPS_INDEX, body={
        "query": query,
        "size": 0,
        "aggs": {
            "ip_stats": {
                "scripted_metric": {
                    "init_script": "state.external = [:]; state.internal = new HashSet()",
                    "map_script": "if (params._source.ips != null) { for (item in params._source.ips) { def ip = item.ip; if (ip == null) continue; def key = ip.toString(); if (item.is_internal == false) { def packets = item.packet_count == null ? 0 : item.packet_count; state.external[key] = (state.external.containsKey(key) ? state.external[key] : 0) + packets; } else if (item.is_internal == true) { state.internal.add(key); } } }",
                    "combine_script": "return ['external': state.external, 'internal': state.internal]",
                    "reduce_script": "def external = [:]; def internal = new HashSet(); for (s in states) { for (e in s.external.entrySet()) { external[e.getKey()] = (external.containsKey(e.getKey()) ? external[e.getKey()] : 0) + e.getValue(); } internal.addAll(s.internal); } return ['external': external, 'internal': internal];"
                }
            }
        }
    })
    ip_stats = res.get("aggregations", {}).get("ip_stats", {}).get("value", {})
    external_map     = ip_stats.get("external", {}) if isinstance(ip_stats, dict) else {}
    internal_values  = ip_stats.get("internal", []) if isinstance(ip_stats, dict) else []
    stats["total_external_ips"] = len(external_map)
    stats["total_internal_ips"] = len(set(internal_values))

    # Replace scripted_metric for top_active_ips with native nested terms+sum agg
    try:
        top_res = es.search(index=PCAP_IPS_INDEX, body={
            "query": query,
            "size": 0,
            "aggs": {
                "ext": {"nested": {"path": "ips"}, "aggs": {
                    "external_only": {"filter": {"term": {"ips.is_internal": False}}, "aggs": {
                    "top_ips": {
                        "terms": {"field": "ips.ip", "size": 10},
                        "aggs": {"packets": {"sum": {"field": "ips.packet_count"}}}
                    }
                    }}
                }}
            }
        })
        buckets = (top_res.get("aggregations", {}).get("ext", {})
                   .get("external_only", {}).get("top_ips", {}).get("buckets", []))
        top_ips_list = [
            {"ip": b["key"], "packets": int(b["packets"]["value"] or 0), "connections": 0}
            for b in buckets
        ]
        # Enrich with connection counts from zeek-conn
        if top_ips_list:
            try:
                ip_set = [r["ip"] for r in top_ips_list]
                conn_res = es.search(index=ZEEK_CONN_INDEX, body={
                    "query": {"terms": {"pcap_id": pcap_ids}} if pcap_ids is not None else {"match_all": {}},
                    "size": 0,
                    "aggs": {"per_ip": {"scripted_metric": {
                        "init_script": "state.map = [:]",
                        "map_script": """
                            if (params._source.connections == null) return;
                            for (c in params._source.connections) {
                                for (def f : ['id.orig_h', 'id.resp_h']) {
                                    def ip = c[f];
                                    if (ip != null && params.ips.contains(ip.toString())) {
                                        def k = ip.toString();
                                        state.map[k] = (state.map.containsKey(k) ? state.map[k] : 0) + 1;
                                    }
                                }
                            }
                        """,
                        "combine_script": "return state.map",
                        "reduce_script": "def out = [:]; for (s in states) { if (s != null) { for (e in s.entrySet()) { out[e.getKey()] = (out.containsKey(e.getKey()) ? out[e.getKey()] : 0) + e.getValue(); } } } return out",
                        "params": {"ips": ip_set}
                    }}}
                })
                conn_map = conn_res.get("aggregations", {}).get("per_ip", {}).get("value") or {}
                for r in top_ips_list:
                    r["connections"] = int(conn_map.get(r["ip"], 0))
            except Exception as ce:
                print(f"_apply_ip_aggs connections enrich error: {ce}")
        stats["top_active_ips"] = top_ips_list
    except Exception as e:
        print(f"_apply_ip_aggs top_active_ips error: {e}")
        stats["top_active_ips"] = []


def _apply_ssl_aggs(es, stats, pcap_ids=None):
    """Run pcap-dns SSL aggregation and update stats in-place."""
    res = es.search(index=PCAP_DNS_INDEX, body={
        "query": {"match_all": {}} if pcap_ids is None else {"terms": {"pcap_id": pcap_ids}} if pcap_ids else {"match_none": {}},
        "size": 0,
        "aggs": {
            "ssl_only": {
                "filter": {"term": {"domains.type.keyword": "ssl"}},
                "aggs": {
                    "labels": {
                        "terms": {"field": "domains.domain.keyword", "size": 1000},
                        "aggs": {"total": {"sum": {"field": "domains.count"}}}
                    }
                }
            }
        }
    })
    buckets = res.get("aggregations", {}).get("ssl_only", {}).get("labels", {}).get("buckets", [])
    ssl_domains_list = sorted(
        [{"label": b["key"], "value": int(b["total"]["value"] or 0)} for b in buckets],
        key=lambda x: x["value"], reverse=True
    )
    stats["top_ssl_domains"] = ssl_domains_list[:10]


def get_global_aggregation_fast(sinkhole_id=None):
    """ES-native global aggregation used by dashboard and API routes."""
    es = get_es()
    empty = {
        "total_external_ips": 0,
        "total_internal_ips": 0,
        "total_bytes": 0,
        "total_packets": 0,
        "total_connections": 0,
        "total_file_size": 0,
        "total_duration": 0.0,
        "total_infected_hosts": 0,
        "infected_hosts": [],
        "infected_hosts_count": 0,
        "total_dns_domains": 0,
        "total_url_domains": 0,
        "total_protocols": 0,
        "total_pcaps": 0,
        "top_dns_domains": [],
        "top_url_domains": [],
        "top_ssl_domains": [],
        "top_active_ips": [],
        "transport_breakdown": [],
        "application_breakdown": [],
        "direction_breakdown": [],
        "protocol_breakdown": []
    }
    if not es:
        return empty

    stats = dict(empty)
    pcap_ids = get_pcap_ids_for_sinkhole(sinkhole_id, es) if sinkhole_id is not None else None
    try:
        query = {"match_all": {}} if sinkhole_id is None else {"term": {"sinkhole_id": sinkhole_id}}
        stats["total_pcaps"] = int(es.count(index=PCAP_METADATA_INDEX, body={"query": query}).get("count", 0))
    except Exception:
        pass
    try:
        _apply_metadata_aggs(es, stats, sinkhole_id=sinkhole_id)
    except Exception as e:
        print(f"get_global_aggregation_fast error: {e}")
    try:
        _apply_ip_aggs(es, stats, pcap_ids=pcap_ids)
    except Exception as e:
        print(f"get_global_aggregation_fast IP error: {e}")
    try:
        _apply_ssl_aggs(es, stats, pcap_ids=pcap_ids)
    except Exception as e:
        print(f"get_global_aggregation_fast SSL error: {e}")
    return stats
