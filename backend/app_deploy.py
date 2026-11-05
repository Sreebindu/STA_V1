import os
import io
import json
import uuid
import urllib3
import boto3
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError
from celery import Celery
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from elastic import get_es
from dotenv import load_dotenv
import elastic
from datetime import datetime, timezone
import hmac
from jwt_auth import (
    RevocationStoreError,
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    ensure_revocation_store,
    revoke_session_tokens,
    rotate_refresh_token,
)

load_dotenv()

def _enrich_rows_with_pcap_appearance_data(rows, pcaps_map=None):
    try:
        if hasattr(elastic, 'enrich_rows_with_pcap_appearance_data'):
            return elastic.enrich_rows_with_pcap_appearance_data(rows, pcaps_map=pcaps_map)
    except Exception as e:
        print(f'[Compat] enrich helper call failed: {e}')

    rows = list(rows or [])
    if not rows:
        return rows

    if pcaps_map is None:
        ip_list = [row.get('ip') for row in rows if row.get('ip')]
        pcaps_map = elastic.get_pcaps_for_ips_bulk(ip_list) if ip_list else {}

    for row in rows:
        ip = row.get('ip')
        entries = pcaps_map.get(ip, []) if isinstance(pcaps_map, dict) else []
        normalized_entries = []
        if isinstance(entries, list):
            normalized_entries = [e for e in entries if isinstance(e, dict)]
        elif isinstance(entries, dict):
            normalized_entries = [entries]

        pcap_names = [entry.get('filename') for entry in normalized_entries if entry.get('filename')]
        pcap_names_text = ', '.join(pcap_names) if pcap_names else ''
        pcap_count = len(pcap_names)
        row['_pcaps'] = normalized_entries
        row['pcap_names'] = pcap_names_text
        row['pcap_name'] = pcap_names_text
        row['pcapName'] = pcap_names_text
        row['pcapNames'] = pcap_names_text
        row['pcap_appearances'] = pcap_names_text
        row['pcap_appearance_names'] = pcap_names_text
        row['pcap_files'] = pcap_names
        row['pcapFiles'] = pcap_names
        row['pcap_file_names'] = pcap_names
        row['pcap_names_list'] = pcap_names
        row['pcap_count'] = pcap_count
        row['pcapCount'] = pcap_count
        row['pcap_appearance_count'] = pcap_count
        row['pcapAppearanceCount'] = pcap_count

    return rows


def get_site_status_context():
    return {}

from helpers import (
    scroll_all_external_ips, rebin_time_series, normalise_labels,
    get_pcap_ssl_domains, get_pcap_ip_counts, build_pcap_overview_response,
    build_global_overview_response, scroll_country_aggregation,
)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

basedir = os.path.abspath(os.path.dirname(__file__))
es = None


@asynccontextmanager
async def lifespan(_app):
    global es
    es = get_es()
    try:
        elastic.create_granular_indexes()
        elastic.create_feedback_index()
    except Exception as error:
        print(f'Warning: Could not create Elasticsearch index: {error}')

    threading.Thread(target=_build_caches, daemon=True).start()
    threading.Thread(target=_cleanup_stale_pdf_files, daemon=True).start()
    yield


app = FastAPI(
    title="Network Traffic Analysis API",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ES_HOST = os.getenv('ES_HOST', 'http://localhost:9200')
print(ES_HOST)

def _build_caches():
    try:
        print('[Cache] Building map-country-cache...')
        elastic.refresh_map_country_cache()
        print('[Cache] map-country-cache done.')
    except Exception as e:
        print(f'[Cache] map-country-cache error: {e}')
    try:
        print('[Cache] Building geo-breakdown-cache...')
        elastic.refresh_geo_breakdown_cache()
        print('[Cache] geo-breakdown-cache done.')
    except Exception as e:
        print(f'[Cache] geo-breakdown-cache error: {e}')

def _cleanup_stale_pdf_files():
    """Delete orphaned PDF files in /tmp/pdf_jobs older than 1 hour on startup."""
    import glob, time as _time
    try:
        cutoff = _time.time() - 3600
        for f in glob.glob('/tmp/pdf_jobs/*.pdf'):
            try:
                if os.path.getmtime(f) < cutoff:
                    os.remove(f)
            except Exception:
                pass
    except Exception as e:
        print(f'[Cleanup] stale PDF cleanup error: {e}')

import threading

celery_client = Celery(broker=os.getenv('REDIS_URL', 'redis://redis:6379/0'))

# ============= API RESPONSE HELPER =============
async def _request_json(request: Request):
    try:
        return await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

def _query_param(request: Request, key, default=None, value_type=str):
    value = request.query_params.get(key)
    if value is None:
        return default
    try:
        return value_type(value)
    except (TypeError, ValueError):
        return default

def _attachment_response(file_object, mimetype=None, as_attachment=False, download_name=None):
    headers = {}
    if as_attachment and download_name:
        from urllib.parse import quote
        headers['Content-Disposition'] = f"attachment; filename*=UTF-8''{quote(download_name, safe='')}"
    return Response(file_object.read(), media_type=mimetype, headers=headers)

def api_response(data, success=True, page=None, per_page=None, total=None, total_pages=None, error=None, meta=None, status_code=200):
    response = {
        'success': success,
        'data': data
    }
    if error:
        response['error'] = error

    if page is not None or per_page is not None or total is not None:
        response['pagination'] = {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': total_pages
        }

    if meta:
        response.update(meta)

    return JSONResponse(content=response, status_code=status_code)


@app.exception_handler(HTTPException)
async def handle_http_exception(_request: Request, error: HTTPException):
    return JSONResponse(
        status_code=error.status_code,
        content={
            'success': False,
            'data': None,
            'error': str(error.detail),
        },
        headers=error.headers,
    )


def require_role(*roles):
    async def dependency(request: Request):
        auth_header = request.headers.get('Authorization', '')
        scheme, _, token = auth_header.partition(' ')
        if scheme.lower() != 'bearer' or not token:
            raise HTTPException(status_code=401, detail='Missing token')
        try:
            current_user = decode_access_token(token.strip())
        except RevocationStoreError as error:
            print(f'[Auth] Token revocation store error: {error}')
            raise HTTPException(
                status_code=503,
                detail='Authentication service is unavailable',
            ) from error
        except RuntimeError as error:
            print(f'[Auth] JWT configuration error: {error}')
            raise HTTPException(
                status_code=503,
                detail='Authentication is not configured',
            ) from error
        except TokenError as error:
            raise HTTPException(
                status_code=401,
                detail='Invalid or expired token',
            ) from error
        if current_user['role'] not in roles:
            raise HTTPException(status_code=403, detail='Insufficient permissions')
        request.state.current_user = current_user
        return current_user

    return dependency


# ============= AUTHENTICATION =============
@app.post('/api/auth/login')
async def login(request: Request):
    credentials = await _request_json(request)
    if not isinstance(credentials, dict):
        return api_response(data=None, success=False, error='Username and password are required', status_code=400)

    username = credentials.get('username')
    password = credentials.get('password')
    if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
        return api_response(data=None, success=False, error='Username and password are required', status_code=400)

    configured_users = (
        ('admin', os.getenv('AUTH_ADMIN_USERNAME', ''), os.getenv('AUTH_ADMIN_PASSWORD', '')),
        ('user', os.getenv('AUTH_USER_USERNAME', ''), os.getenv('AUTH_USER_PASSWORD', '')),
    )
    if (
        any(not configured_username or not configured_password for _, configured_username, configured_password in configured_users)
        or configured_users[0][1] == configured_users[1][1]
    ):
        return api_response(data=None, success=False, error='Authentication is not configured', status_code=503)

    role = next(
        (
            configured_role
            for configured_role, configured_username, configured_password in configured_users
            if hmac.compare_digest(
                username.encode('utf-8', errors='surrogatepass'),
                configured_username.encode('utf-8', errors='surrogatepass'),
            )
            and hmac.compare_digest(
                password.encode('utf-8', errors='surrogatepass'),
                configured_password.encode('utf-8', errors='surrogatepass'),
            )
        ),
        None,
    )
    if role is None:
        return api_response(data=None, success=False, error='Invalid username or password', status_code=401)

    return _issue_token_pair(username, role)


@app.post('/api/auth/refresh')
async def refresh_tokens(request: Request):
    credentials = await _request_json(request)
    refresh_token = credentials.get('refresh_token') if isinstance(credentials, dict) else None
    access_token = credentials.get('access_token') if isinstance(credentials, dict) else None
    if not isinstance(refresh_token, str) or not refresh_token:
        return api_response(data=None, success=False, error='Refresh token is required', status_code=400)

    try:
        claims = decode_refresh_token(refresh_token)
        rotate_refresh_token(refresh_token, access_token)
    except RevocationStoreError as e:
        print(f'[Auth] Token revocation store error: {e}')
        return api_response(data=None, success=False, error='Authentication service is unavailable', status_code=503)
    except RuntimeError as e:
        print(f'[Auth] JWT configuration error: {e}')
        return api_response(data=None, success=False, error='Authentication is not configured', status_code=503)
    except TokenError:
        return api_response(data=None, success=False, error='Invalid or expired refresh token', status_code=401)

    return _issue_token_pair(claims['sub'], claims['role'])


@app.get('/api/auth/validate')
def validate_access_token(request: Request):
    auth_header = request.headers.get('Authorization', '')
    scheme, _, token = auth_header.partition(' ')
    if scheme.lower() != 'bearer' or not token:
        return api_response(data=None, success=False, error='Missing token', status_code=401)
    try:
        claims = decode_access_token(token.strip())
    except RevocationStoreError as e:
        print(f'[Auth] Token revocation store error: {e}')
        return api_response(data=None, success=False, error='Authentication service is unavailable', status_code=503)
    except RuntimeError as e:
        print(f'[Auth] JWT configuration error: {e}')
        return api_response(data=None, success=False, error='Authentication is not configured', status_code=503)
    except TokenError:
        return api_response(data=None, success=False, error='Invalid or expired token', status_code=401)
    return api_response(data={'user': {'username': claims['sub'], 'role': claims['role']}})


@app.post('/api/auth/logout')
async def logout(request: Request):
    credentials = await _request_json(request)
    access_token = credentials.get('access_token') if isinstance(credentials, dict) else None
    refresh_token = credentials.get('refresh_token') if isinstance(credentials, dict) else None
    try:
        revoke_session_tokens(access_token, refresh_token)
    except RevocationStoreError as e:
        print(f'[Auth] Token revocation store error: {e}')
        return api_response(data=None, success=False, error='Authentication service is unavailable', status_code=503)
    except RuntimeError as e:
        print(f'[Auth] JWT configuration error: {e}')
        return api_response(data=None, success=False, error='Authentication is not configured', status_code=503)
    return api_response(data={'revoked': True})


def _issue_token_pair(username, role):
    try:
        ensure_revocation_store()
        access_token, access_expires_at = create_access_token(username, role)
        refresh_token, refresh_expires_at = create_refresh_token(username, role)
    except RevocationStoreError as e:
        print(f'[Auth] Token revocation store error: {e}')
        return api_response(data=None, success=False, error='Authentication service is unavailable', status_code=503)
    except RuntimeError as e:
        print(f'[Auth] JWT configuration error: {e}')
        return api_response(data=None, success=False, error='Authentication is not configured', status_code=503)

    return api_response(data={
        'access_token': access_token,
        'access_expires_at': access_expires_at,
        'refresh_token': refresh_token,
        'refresh_expires_at': refresh_expires_at,
        'token_type': 'Bearer',
        'user': {'username': username, 'role': role},
    })


def sanitize_ip_records_for_insights(ip_records):
    cleaned_records = []
    for record in ip_records or []:
        if not isinstance(record, dict):
            continue
        cleaned = {k: v for k, v in record.items() if k not in ('is_internal', 'location','latitude','longitude')}
        cleaned_records.append(cleaned)
    return cleaned_records

def sanitize_ip_records_for_map(ip_records):
    cleaned_records = []
    for record in ip_records or []:
        if not isinstance(record, dict):
            continue
        rec = dict(record)
        # Flatten location: {lat, lon} -> latitude/longitude (pcap-ips format)
        loc = rec.get('location')
        if (rec.get('latitude') is None or rec.get('longitude') is None) and isinstance(loc, dict):
            lat = loc.get('lat')
            lon = loc.get('lon')
            if lat is not None:
                rec['latitude'] = lat
            if lon is not None:
                rec['longitude'] = lon
        # Flatten geo: {latitude, longitude} -> latitude/longitude (ip-intelligence format)
        geo = rec.get('geo')
        if (rec.get('latitude') is None or rec.get('longitude') is None) and isinstance(geo, dict):
            lat = geo.get('latitude') if geo.get('latitude') is not None else geo.get('lat')
            lon = geo.get('longitude') if geo.get('longitude') is not None else geo.get('lon')
            if lat is not None:
                rec['latitude'] = lat
            if lon is not None:
                rec['longitude'] = lon
        # Flatten city/country/isp from geo if missing at top level
        if isinstance(geo, dict):
            if not rec.get('city'):
                rec['city'] = geo.get('city')
            if not rec.get('country'):
                rec['country'] = geo.get('country')
            if not rec.get('isp'):
                rec['isp'] = geo.get('isp')
        rec.pop('is_internal', None)
        rec.pop('location', None)
        cleaned_records.append(rec)
    return cleaned_records


# ============= HEALTH CHECK =============
@app.get('/api/health')
def health():
    try:
        if es and es.ping():
            return JSONResponse({"status": "ok"})
        return JSONResponse({"status": "es_down"}, status_code=500)
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)

# ============= IP INTELLIGENCE PROGRESS =============
@app.get('/api/ip-intelligence/progress')


def ip_intelligence_progress(current_user: dict = Depends(require_role('admin'))):
    try:
        total_unique = len(scroll_all_external_ips(es, elastic.PCAP_IPS_INDEX))
        done = es.count(index=elastic.IP_INTEL_INDEX, body={"query": {"match_all": {}}})['count']
        remaining = max(total_unique - done, 0)
        pct = round(done / total_unique * 100, 2) if total_unique else 0
        return api_response(data={
            'total_unique_ips': total_unique,
            'completed': done,
            'remaining': remaining,
            'progress_pct': pct,
        })
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)
    

# ============= TIMELINE / TIME SERIES =============
@app.get('/api/pcaps/{pcap_id}/timeline')


def get_time_series(request: Request, pcap_id: str, current_user: dict = Depends(require_role('admin'))):
    try:
        data = elastic.get_time_series(pcap_id)
        target_bins = _query_param(request, 'bins', 60, int)
        if data and len(data) > target_bins:
            try:
                data = rebin_time_series(data, target_bins)
            except Exception as e:
                print(f"Dynamic binning error: {e}")
        if data:
            normalise_labels(data)
        return api_response(data=data)
    except Exception as e:
        return api_response(data=[], success=False, error=str(e), status_code=500)


# ============= STATS =============
@app.get('/api/stats')

def get_stats(request: Request, current_user: dict = Depends(require_role('admin'))):
    try:
        requested_pcap_id = _query_param(request, 'pcap_id', None, str) or None
        if requested_pcap_id:
            data = elastic.get_dashboard_document(requested_pcap_id)
        else:
            data = elastic.get_latest_dashboard_document(
                sinkhole_id=elastic.GLOBAL_DASHBOARD_SINKHOLE_ID
            )
        if not data:
            data = {}
        data.update(get_site_status_context())
        return api_response(data=data)
    except Exception as error:
        return api_response(data=None, success=False, error=str(error), status_code=500)


# ============= RECENT LOGS =============
@app.get('/api/recent-logs/{log_type}')


def get_recent_logs(request: Request, log_type: str, current_user: dict = Depends(require_role('admin'))):
    try:
        page = _query_param(request, 'page', 1, int)
        per_page = _query_param(request, 'per_page', 50, int)
        pcap_id = _query_param(request, 'pcap_id', None, str)

        result = elastic.get_recent_logs_from_es(
            page=page,
            per_page=per_page,
            pcap_id=pcap_id
        )
        return api_response(
            data=result.get('logs', []),
            page=result.get('page'),
            per_page=result.get('per_page'),
            total=result.get('total'),
            total_pages=result.get('total_pages')
        )
    except Exception as e:
        return api_response(data=[], success=False, error=str(e), status_code=500)


# ============= PCAP OVERVIEW =============
@app.get('/api/overview')
@app.get('/api/dashboard/overview')
@app.get('/api/pcaps/{pcap_id}/summary')


def get_overview(request: Request, current_user: dict = Depends(require_role('admin'))):
    pcap_id = request.path_params.get('pcap_id')
    try:
        scoped_pcap_id = pcap_id or _query_param(request, 'pcap_id', None, str)
        if scoped_pcap_id:
            data = elastic.get_dashboard_document(scoped_pcap_id)
            if not data or (
                data.get('file_id') != scoped_pcap_id
                and data.get('pcap_id') != scoped_pcap_id
            ):
                return api_response(data=None, success=False, error=f'No analysis found for {scoped_pcap_id}', status_code=404)
            ssl_domains = get_pcap_ssl_domains(es, scoped_pcap_id)
            internal_ip_count, external_ip_count = get_pcap_ip_counts(es, scoped_pcap_id)
            return api_response(data=build_pcap_overview_response(data, ssl_domains, internal_ip_count, external_ip_count))
        return api_response(data=build_global_overview_response(
            es, elastic, sinkhole_id=elastic.GLOBAL_DASHBOARD_SINKHOLE_ID
        ))
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


# ============= INSIGHTS =============
@app.get('/api/insights')
@app.get('/api/pcaps/{pcap_id}/insights')


def get_insights(request: Request, current_user: dict = Depends(require_role('admin'))):
    pcap_id = request.path_params.get('pcap_id', None)

    try:
        scoped_pcap_id = pcap_id or _query_param(request, 'pcap_id', None, str)
        if scoped_pcap_id:
            data = elastic.get_dashboard_document(scoped_pcap_id)
            if not data or (
                data.get('file_id') != scoped_pcap_id
                and data.get('pcap_id') != scoped_pcap_id
            ):
                return api_response(data=None, success=False, error=f'No analysis found for {scoped_pcap_id}', status_code=404)
            sf_counts = elastic.get_sf_connection_counts_for_pcap(scoped_pcap_id)

            def _attach_sf(ip_records):
                for rec in ip_records:
                    rec['connections'] = sf_counts.get(rec.get('ip'), 0)
                return ip_records

            geo_breakdown = elastic.get_ip_breakdown(scoped_pcap_id)
            return api_response(data={
                'pcap_insights': {
                    'internal_ips':      _attach_sf(sanitize_ip_records_for_insights(elastic.get_internal_ips_for_pcap(scoped_pcap_id))),
                    'external_ips':      sanitize_ip_records_for_insights(elastic.get_external_ips_for_pcap(scoped_pcap_id)),
                    'protocols':         data.get('protocols', []),
                    'ports':             data.get('ports', []),
                    'dns_queries':       elastic.get_dns_queries_for_pcap(scoped_pcap_id),
                    'domains':           data.get('top_dns_domains', []),
                    'urls':              data.get('top_url_domains', []),
                    'files_and_payloads': elastic.get_pcap_files(scoped_pcap_id),
                    'user_agents':       data.get('user_agents', []),
                    'ftp_session':       data.get('ftp_session') or None,
                    'top_countries':     (geo_breakdown.get('countries') or [])[:10],
                    'top_isps':          (geo_breakdown.get('isps') or [])[:10],
                    'top_cities':        (geo_breakdown.get('cities') or [])[:10],
                }
            })
        sinkhole_id = elastic.GLOBAL_DASHBOARD_SINKHOLE_ID
        def _get_infected_hosts():
            try:
                ih_res = es.search(
                    index=elastic.PCAP_METADATA_INDEX,
                    body={
                        "query": {"bool": {"filter": [{"term": {"sinkhole_id": sinkhole_id}}], "must_not": [{"terms": {"infected_host.keyword": ["Unknown", "N/A", "-", "None", "null", ""]}}]}},
                        "_source": ["infected_host"],
                        "size": 10000
                    }
                )
                return sorted({
                    infected_host
                    for hit in ih_res["hits"]["hits"]
                    for infected_host in [hit["_source"].get("infected_host", "").strip()]
                    if infected_host
                    and infected_host.lower() not in ('unknown', 'n/a', '-', 'none', 'null', '')
                    and '::' not in infected_host
                    and not infected_host.startswith('231.')
                    and not infected_host.startswith('224.')
                    and not infected_host.startswith('239.')
                })
            except Exception:
                return []

        with ThreadPoolExecutor(max_workers=3) as executor:
            global_stats_future = executor.submit(
                elastic.get_global_aggregation,
                sinkhole_id=sinkhole_id,
            )
            ip_breakdown_future = executor.submit(
                elastic.get_ip_breakdown,
                sinkhole_id=sinkhole_id,
            )
            infected_hosts_future = executor.submit(_get_infected_hosts)
            global_stats = global_stats_future.result()
            ip_breakdown = ip_breakdown_future.result()
            infected_hosts = infected_hosts_future.result()

        return api_response(data={
            'insights_trends': {
                'infected_hosts':     infected_hosts,
                'infected_hosts_count': len(infected_hosts),
                'top_active_ips':    (global_stats.get('top_active_ips') or [])[:10],
                'top_countries':      (ip_breakdown.get('countries') or [])[:10],
                'top_isps':           (ip_breakdown.get('isps') or [])[:10],
                'top_cities':         (ip_breakdown.get('cities') or [])[:10],
            }
        })
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


# ============= LEGACY ROUTES =============
@app.get('/api/pcap/{pcap_id}')


def get_pcap_analysis(
    request: Request,
    pcap_id: str,
    current_user: dict = Depends(require_role('admin')),
):
    return get_overview(request, current_user)


@app.get('/api/pcap/latest')


def get_latest_pcap_analysis(current_user: dict = Depends(require_role('admin'))):
    try:
        data = elastic.get_latest_dashboard_document()
        if data:
            data.pop('recent_connections', None)
            data.pop('file_payloads', None)
            return api_response(data=data)
        return api_response(data=None, success=False, error='No dashboard documents found in Elasticsearch', status_code=404)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


# ============= CONNECTIONS =============
@app.get('/api/pcaps/{pcap_id}/connections')
@app.get('/api/pcap/{pcap_id}/connections')


def get_pcap_connections(request: Request, pcap_id: str, current_user: dict = Depends(require_role('admin'))):
    try:
        page     = _query_param(request, 'page', 1, int)
        per_page = _query_param(request, 'per_page', 40, int)
        result   = elastic.get_recent_logs_from_es(
            page=page,
            per_page=max(1, min(per_page, 100)),
            pcap_id=pcap_id,
        )
        return api_response(
            data=result.get('logs', []),
            page=result.get('page'),
            per_page=result.get('per_page'),
            total=result.get('total'),
            total_pages=result.get('total_pages')
        )
    except Exception as e:
        return api_response(data=[], success=False, error=str(e), status_code=500)


@app.get('/api/pcaps/{pcap_id}/connections/export')


def export_pcap_connections(pcap_id: str, current_user: dict = Depends(require_role('admin'))):
    import csv
    import tempfile
    import subprocess

    total = elastic.get_recent_logs_from_es(pcap_id=pcap_id, page=1, per_page=1).get('total', 0)
    if not total:
        return api_response(data=None, success=False, error='No connections found for this pcap', status_code=404)

    logs = elastic.get_recent_logs_from_es(pcap_id=pcap_id, page=1, per_page=total).get('logs', [])

    fieldnames = ['Timestamp', 'Source IP', 'Dest IP', 'Port', 'Protocol', 'Duration', 'Service', 'Conn_state_short', 'Conn_state_long', 'Bytes']

    csv_buf = io.StringIO()
    writer = csv.DictWriter(csv_buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in logs:
        writer.writerow({
            'Timestamp':        row.get('timestamp'),
            'Source IP':        row.get('src_ip'),
            'Dest IP':          row.get('dest_ip'),
            'Port':             row.get('resp_port'),
            'Protocol':         row.get('proto'),
            'Duration':         row.get('duration'),
            'Service':          row.get('service'),
            'Conn_state_short': row.get('conn_state'),
            'Conn_state_long':  row.get('conn_state_desc'),
            'Bytes':            row.get('orig_bytes') or None,
        })

    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = os.path.join(tmpdir, f'{pcap_id}_connections.csv')
        zip_path = os.path.join(tmpdir, f'{pcap_id}_connections.zip')
        with open(csv_path, 'w', encoding='utf-8', newline='') as f:
            f.write(csv_buf.getvalue())
        subprocess.run(
            ['zip', '-j', '-P', f'sta#@{pcap_id}', zip_path, csv_path],
            check=True, capture_output=True
        )
        with open(zip_path, 'rb') as f:
            zip_buf = io.BytesIO(f.read())
    zip_buf.seek(0)
    return _attachment_response(zip_buf, mimetype='application/zip', as_attachment=True,
                     download_name=f'{pcap_id}_connections.zip')


# ============= DNS REQUESTS (URLs + connected IPs) =============
@app.get('/api/pcaps/{set_id}/dns-sinkhole')

def get_dns_requests(
    request: Request,
    set_id: int,
    current_user: dict = Depends(require_role('admin', 'user')),
):
    """List URLs seen in HTTP traffic with the client IPs that connected to them.

    Each record includes the URL, connected IP count, total connections, and
    the connected IPs with their ISP, latitude and longitude.
    """
    try:
        page     = _query_param(request, 'page', 1, int)
        per_page = _query_param(request, 'per_page', 50, int)
        search   = _query_param(request, 'search', '', str)
        result   = elastic.get_dns_requests_for_sinkhole(
            sinkhole_id=set_id,
            page=page,
            per_page=per_page,
            search=search,
        )
        return api_response(
            data=result.get('requests', []),
            page=result.get('page'),
            per_page=result.get('per_page'),
            total=result.get('total'),
            total_pages=result.get('total_pages'),
        )
    except Exception as e:
        return api_response(data=[], success=False, error=str(e), status_code=500)


@app.get('/api/pcaps/{set_id}/dns-sinkhole/domains/{domain}/details')
def get_dns_sinkhole_domain_details(
    set_id: int,
    domain: str,
    current_user: dict = Depends(require_role('admin', 'user')),
):
    try:
        return api_response(
            data=elastic.get_dns_sinkhole_domain_details(set_id, domain)
        )
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


@app.get('/api/pcaps/{set_id}/dns-sinkhole/summary')
def get_dns_sinkhole_summary(
    set_id: int,
    current_user: dict = Depends(require_role('admin', 'user')),
):
    """Return DNS-sinkhole totals for the requested sinkhole set."""
    try:
        return api_response(data=elastic.get_dns_sinkhole_summary(set_id))
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


# ============= FILES =============
@app.get('/api/pcap/{pcap_id}/files')


def get_pcap_files(pcap_id: str, current_user: dict = Depends(require_role('admin'))):
    try:
        data = elastic.get_pcap_files(pcap_id)
        return api_response(data=data)
    except Exception as e:
        return api_response(data=[], success=False, error=str(e), status_code=500)


# ============= PCAP LIST =============
@app.get('/api/pcap/all')


def get_all_pcap_analyses(current_user: dict = Depends(require_role('admin'))):
    try:
        _es = get_es()
        if not _es:
            return api_response(data=None, success=False, error='Elasticsearch unavailable', status_code=503)
        res = _es.search(
            index=elastic.PCAP_METADATA_INDEX,
            body={
                "query": {"match_all": {}},
                "_source": ["pcap_id", "pcap_filename", "file_name", "file_size", "total_packets", "duration_seconds", "unique_ips", "analysis_timestamp"],
                "size": 10000,
                "sort": [{"analysis_timestamp": {"order": "desc", "unmapped_type": "date"}}]
            }
        )
        data = [hit["_source"] for hit in res["hits"]["hits"]]
        return api_response(data=data, total=len(data))
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


# ============= GEO REPORT =============
@app.get('/api/reports/geo')


def get_geo_report(request: Request, current_user: dict = Depends(require_role('admin', 'user'))):
    try:
        pcap_id = _query_param(request, 'pcap_id', None, str)
        data = elastic.get_geo_aggregation(pcap_id)

        def _shape(entries):
            shaped = []
            for c in entries or []:
                packets = int(c.get("packets", 0) or 0)
                shaped.append({
                    "name": c.get("name"),
                    "packets": packets,
                    "packet_count": packets,
                    "connections": int(c.get("connections", 0) or 0),
                })
            return shaped

        data = {
            "countries": _shape(data.get("countries")),
            "isps":      _shape(data.get("isps")),
        }
        return api_response(data=data)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


# ============= REPORT DETAILS =============
@app.get('/api/reports/details/{report_type}')


def get_report_type_list(report_type: str, current_user: dict = Depends(require_role('admin', 'user'))):
    try:
        data = elastic.get_geo_aggregation()
        key_map = {'country': 'countries', 'isp': 'isps', 'city': 'cities'}
        key = key_map.get(report_type.lower())
        if not key:
            return api_response(data=None, success=False, error=f'Unknown report type: {report_type}', status_code=400)
        return api_response(data=data.get(key, []), meta={"report_type": report_type})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


@app.get('/api/reports/details/{report_type}/{report_value}')
@app.get('/api/reports/details/{report_type}/{report_value:path}', include_in_schema=False)


def get_report_details_path(report_type: str, report_value: str, current_user: dict = Depends(require_role('admin', 'user'))):
    try:
        data = _enrich_rows_with_pcap_appearance_data(
            sanitize_ip_records_for_map(elastic.get_report_details(report_type, report_value))
        )
        for row in data:
            row.setdefault('packets', row.get('packet_count', 0))
            row.setdefault('packet_count', row.get('packets', 0))
        return api_response(data=data, meta={
            "total_unique_ips": len(data),
            "report_type": report_type,
            "filter_value": report_value
        })
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


@app.get('/api/reports/details/{report_type}/{report_value}/export')
@app.get('/api/reports/details/{report_type}/{report_value:path}/export', include_in_schema=False)
def export_report_details_pdf_route(
    request: Request,
    report_type: str,
    report_value: str,
    current_user: dict = Depends(require_role('admin', 'user')),
):
    return export_report_details_pdf(request, report_type, report_value, current_user)


@app.get('/api/reports/{pcap_id}/{report_type}/{report_value}/export')
@app.get(
    '/api/reports/{pcap_id}/{report_type}/{report_value:path}/export',
    include_in_schema=False,
)
def export_pcap_report_pdf_route(
    request: Request,
    pcap_id: str,
    report_type: str,
    report_value: str,
    current_user: dict = Depends(require_role('admin', 'user')),
):
    return export_pcap_report_pdf(
        request,
        pcap_id,
        report_type,
        report_value,
        current_user,
    )


@app.get('/api/reports/{pcap_id}/{report_type}/{report_value:path}')
def get_pcap_report_details_route(
    pcap_id: str,
    report_type: str,
    report_value: str,
    current_user: dict = Depends(require_role('admin', 'user')),
):
    return get_pcap_report_details(
        pcap_id,
        report_type,
        report_value,
        current_user,
    )


@app.get('/api/reports/{report_type}/{report_value}')
@app.get('/api/reports/{report_type}/{report_value:path}', include_in_schema=False)


def get_global_report_details(report_type: str, report_value: str, current_user: dict = Depends(require_role('admin', 'user'))):
    try:
        data = _enrich_rows_with_pcap_appearance_data(
            sanitize_ip_records_for_map(elastic.get_report_details(report_type, report_value))
        )
        for row in data:
            row.setdefault('packets', row.get('packet_count', 0))
            row.setdefault('packet_count', row.get('packets', 0))
        return api_response(data=data, meta={
            "total_unique_ips": len(data),
            "report_type": report_type,
            "filter_value": report_value
        })
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


def get_pcap_report_details(pcap_id: str, report_type: str, report_value: str, current_user: dict = Depends(require_role('admin', 'user'))):
    try:
        data = _enrich_rows_with_pcap_appearance_data(
            sanitize_ip_records_for_map(elastic.get_pcap_report_details(pcap_id, report_type, report_value))
        )
        for row in data:
            row.setdefault('packets', row.get('packet_count', 0))
            row.setdefault('packet_count', row.get('packets', 0))
        return api_response(data=data, meta={
            "total_unique_ips": len(data),
            "report_type": report_type,
            "filter_value": report_value,
            "pcap_id": pcap_id
        })
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


# ============= GLOBAL STATS =============
@app.get('/api/stats/global')


def get_global_stats(current_user: dict = Depends(require_role('admin'))):
    try:
        data = elastic.get_global_aggregation(
            sinkhole_id=elastic.GLOBAL_DASHBOARD_SINKHOLE_ID
        )
        return api_response(data=data)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


# ============= PCAP LIBRARY =============
@app.get('/api/pcaps')
@app.get('/api/pcaps/{sinkhole_id}')


def get_pcaps(request: Request, current_user: dict = Depends(require_role('admin', 'user'))):
    sinkhole_id = int(request.path_params.get('sinkhole_id', 1))

    try:
        _es = get_es()
        if not _es:
            return api_response(data=[], success=False, error='Elasticsearch unavailable', status_code=503)

        search = _query_param(request, 'search', '', str).lower()
        page = max(1, _query_param(request, 'page', 1, int))
        return_all = _query_param(request, 'all', 0, int) == 1
        per_page = 10000 if return_all else min(100, max(1, _query_param(request, 'per_page', 50, int)))
        sort_by = _query_param(request, 'sort_by', 'random', str)
        sort_order = _query_param(request, 'sort_order', 'desc', str).lower()
        random_seed = _query_param(request, 'random_seed', 0, int)
        date_from = _query_param(request, 'date_from', '', str)
        date_to = _query_param(request, 'date_to', '', str)
        if sort_by not in {"random", "size", "duration", "packets", "date", "external_ips"}:
            sort_by = "random"

        filters = []
        if sinkhole_id is not None:
            filters.append({"term": {"sinkhole_id": sinkhole_id}})
        if search:
            filters.append({"wildcard": {"pcap_filename": {"value": f"*{search}*", "case_insensitive": True}}})
        if date_from:
            filters.append({
                "bool": {
                    "should": [
                        {"bool": {"filter": [
                            {"exists": {"field": "start_time_utc"}},
                            {"range": {"start_time_utc": {"gte": date_from}}},
                        ]}},
                        {"bool": {"filter": [
                            {"bool": {"must_not": [{"exists": {"field": "start_time_utc"}}]}},
                            {"range": {"end_time_utc": {"gte": date_from}}},
                        ]}},
                    ],
                    "minimum_should_match": 1,
                }
            })
        if date_to:
            end_of_day = f"{date_to}T23:59:59.999Z"
            filters.append({
                "bool": {
                    "should": [
                        {"bool": {"filter": [
                            {"exists": {"field": "end_time_utc"}},
                            {"range": {"end_time_utc": {"lte": end_of_day}}},
                        ]}},
                        {"bool": {"filter": [
                            {"bool": {"must_not": [{"exists": {"field": "end_time_utc"}}]}},
                            {"range": {"start_time_utc": {"lte": end_of_day}}},
                        ]}},
                    ],
                    "minimum_should_match": 1,
                }
            })

        query = {"bool": {"filter": filters}} if filters else {"match_all": {}}
        sort_fields = {
            "size": "file_size",
            "duration": "duration_seconds",
            "packets": "total_packets",
            "date": "start_time_utc",
        }
        sort_direction = sort_order if sort_order in {"asc", "desc"} else "desc"
        if sort_by == "random":
            query = {
                "function_score": {
                    "query": query,
                    "random_score": {"seed": random_seed, "field": "_seq_no"},
                }
            }
            sort = [{"_score": {"order": "desc"}}]
        else:
            sort = [{
                sort_fields.get(sort_by, "analysis_timestamp"): {
                    "order": sort_direction,
                    "unmapped_type": "date" if sort_by == "date" else "long",
                    "missing": "_last",
                }
            }]

        external_ip_sort = sort_by == "external_ips"
        res = _es.search(
            index=elastic.PCAP_METADATA_INDEX,
            body={
                "query": query,
                "_source": ["pcap_id", "pcap_filename", "file_name", "file_size", "total_packets", "duration_seconds", "start_time_utc", "end_time_utc"],
                "from": 0 if external_ip_sort or return_all else (page - 1) * per_page,
                "size": 10000 if external_ip_sort or return_all else per_page,
                "track_total_hits": True,
                "sort": sort,
            }
        )

        hits = res["hits"]["hits"]
        total_value = res["hits"]["total"]
        total = total_value["value"] if isinstance(total_value, dict) else total_value
        matching_pcap_ids = [
            hit.get("_source", {}).get("pcap_id")
            for hit in hits
            if hit.get("_source", {}).get("pcap_id")
        ]
        ip_source_fields = [
            "pcap_id",
            "ips.ip",
            "ips.is_internal",
            "external_ips.ip",
            "internal_ips.ip",
        ]

        if external_ip_sort:
            ip_docs = elastic.get_pcap_ip_docs(
                matching_pcap_ids,
                _es,
                source_fields=ip_source_fields,
            )
            ip_count_map = {
                pcap_id: len(doc.get("external_ips") or [])
                for pcap_id, doc in ip_docs.items()
            }
            hits.sort(
                key=lambda hit: ip_count_map.get(hit.get("_source", {}).get("pcap_id"), 0),
                reverse=sort_direction == "desc",
            )
            if not return_all:
                offset = (page - 1) * per_page
                hits = hits[offset:offset + per_page]
            if search or date_from or date_to:
                repository_stats = elastic.get_repository_stats(sinkhole_id=sinkhole_id)
            else:
                repository_stats = elastic.get_repository_stats(
                    sinkhole_id=sinkhole_id,
                    pcap_ip_docs=ip_docs,
                )
        else:
            pcap_ids = [
                hit.get("_source", {}).get("pcap_id")
                for hit in hits
                if hit.get("_source", {}).get("pcap_id")
            ]
            with ThreadPoolExecutor(max_workers=2) as executor:
                ip_docs_future = executor.submit(
                    elastic.get_pcap_ip_docs,
                    pcap_ids,
                    _es,
                    source_fields=ip_source_fields,
                )
                repository_stats_future = executor.submit(
                    elastic.get_repository_stats,
                    sinkhole_id=sinkhole_id,
                    include_observed_ips=not (return_all and not search and not date_from and not date_to),
                )
                ip_docs = ip_docs_future.result()
                repository_stats = repository_stats_future.result()
            if return_all and not search and not date_from and not date_to:
                repository_stats["observed_ips"] = elastic.count_observed_ips(ip_docs)
            ip_count_map = {
                pcap_id: len(doc.get("external_ips") or [])
                for pcap_id, doc in ip_docs.items()
            }

        all_pcaps = []
        for hit in hits:
            src = hit["_source"]
            pcap_id = src.get("pcap_id")
            filename = src.get("pcap_filename") or src.get("file_name") or ""

            all_pcaps.append({
                "pcap_id": pcap_id,
                "filename": filename,
                "size": src.get("file_size") or 0,
                "packets": src.get("total_packets") or 0,
                "duration": src.get("duration_seconds") or 0,
                "ip_count": ip_count_map.get(pcap_id, 0),
                "start_time": src.get("start_time_utc"),
                "end_time": src.get("end_time_utc"),
            })

        return api_response(
            data=all_pcaps,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page,
            meta={"repository_stats": repository_stats}
        )
    except Exception as e:
        print(f"Error in /api/pcaps: {e}")
        return api_response(data=[], success=False, error=str(e), status_code=500)


@app.get('/api/pcaps/set/{sinkhole_id}')


def get_pcaps_set(
    request: Request,
    sinkhole_id: int,
    current_user: dict = Depends(require_role('admin', 'user')),
):
    """Return pcaps for a given sinkhole set (filtered by sinkhole_id)."""
    return get_pcaps(request, current_user)


# ============= MAP =============
@app.get('/api/map')


def get_map_data(request: Request, current_user: dict = Depends(require_role('admin'))):
    try:
        pcap_id = _query_param(request, 'pcap_id', None, str)
        if pcap_id:
            data = sanitize_ip_records_for_map(elastic.get_external_ips_for_pcap(pcap_id))
            for rec in data:
                rec.setdefault('packets', rec.get('packet_count', 0))
                rec.setdefault('packet_count', rec.get('packets', 0))
            total_packets = sum(int(rec.get('packet_count') or 0) for rec in data)
            return api_response(data={"external_ips": data}, meta={
                "total_ips": len(data),
                "total_packets": total_packets,
                "pcap_id": pcap_id,
            })

        from aggregations import get_country_city_map, get_external_ips_global
        sinkhole_id = elastic.GLOBAL_DASHBOARD_SINKHOLE_ID
        locations = get_country_city_map(sinkhole_id=sinkhole_id)
        external_ips = get_external_ips_global(sinkhole_id=sinkhole_id)
        total_packets = sum(int(rec.get('packet_count') or 0) for rec in external_ips)
        return api_response(
            data=locations,
            meta={
                "total_locations": len(locations),
                "external_ips": external_ips,
                "total_ips": len(external_ips),
                "total_packets": total_packets,
            },
        )
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


@app.get('/api/map/external-ips')


def get_global_map_data(current_user: dict = Depends(require_role('admin'))):
    try:
        countries = elastic.get_map_country_cache()
        if not countries:
            pcap_ids = elastic.get_pcap_ids_for_sinkhole(elastic.GLOBAL_DASHBOARD_SINKHOLE_ID, es)
            country_data, country_packets, country_captures = scroll_country_aggregation(
                es, elastic.PCAP_IPS_INDEX, pcap_ids=pcap_ids
            )
            countries = [
                {"name": c, "count": n, "packets": country_packets[c], "captures": len(country_captures[c])}
                for c, n in sorted(country_data.items(), key=lambda x: x[1], reverse=True)
            ]
        return api_response(data=countries, meta={"total_countries": len(countries)})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


@app.get('/api/map/external-ips/export')


def export_external_ips(current_user: dict = Depends(require_role('admin'))):
    try:
        from aggregations import get_all_external_ips
        rows = get_all_external_ips(
            limit=10000, sinkhole_id=elastic.GLOBAL_DASHBOARD_SINKHOLE_ID
        )  # kept at 10000 per requirement
        response = api_response(data=rows, meta={"total_ips": len(rows)})
        response.headers['Content-Disposition'] = 'attachment; filename=external_ips.json'
        return response
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


# ============= IP SCAN =============
@app.get('/api/ip/scan/{ip_address}')


def scan_ip_details(ip_address: str, current_user: dict = Depends(require_role('admin'))):
    try:
        data = elastic.get_ip_scan(ip_address)
        if data:
            if 'ports' in data and isinstance(data['ports'], list):
                data['ports'] = [
                    {k: v for k, v in port.items() if k not in ('http', 'tls', 'scripts')}
                    for port in data['ports']
                ]
            return api_response(data=data)

        geo = elastic.get_ip_geo_from_pcap_ips(ip_address)
        partial = {
            'ip': ip_address,
            'status': 'pending',
            'geo': geo,
            'asn': geo.get('asn'),
            'rdns': 'N/A',
            'hostnames': [],
            'whois': {},
            'os_info': {},
            'dnsbl': {'listed': None, 'total_listings': 0, 'providers': []},
            'ports': [],
        }
        return api_response(data=partial, success=True)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


# ============= ISPs (set-wise, from pcap-ips) =============
@app.get('/api/pcaps/set/{sinkhole_id}/isps')

def list_isps_for_set(request: Request, sinkhole_id: int, current_user: dict = Depends(require_role('admin', 'user'))):
    """List ISPs (with IP + packet counts) for a sinkhole set."""
    try:
        page     = _query_param(request, 'page', 1, int)
        per_page = _query_param(request, 'per_page', 50, int)
        search   = _query_param(request, 'search', '', str)
        result   = elastic.list_isps_for_sinkhole(sinkhole_id, page=page, per_page=per_page, search=search)
        return api_response(
            data=result.get('isps', []),
            page=result.get('page'),
            per_page=result.get('per_page'),
            total=result.get('total'),
            total_pages=result.get('total_pages'),
            meta={"sinkhole_id": sinkhole_id},
        )
    except Exception as e:
        return api_response(data=[], success=False, error=str(e), status_code=500)


@app.get('/api/pcaps/set/{sinkhole_id}/isps/{isp:path}/ips')

def get_ips_by_isp_for_set(request: Request, sinkhole_id: int, isp: str, current_user: dict = Depends(require_role('admin', 'user'))):
    """Return connected IPs for a given ISP within a sinkhole set."""
    try:
        page     = _query_param(request, 'page', 1, int)
        per_page = _query_param(request, 'per_page', 100, int)
        result   = elastic.get_ips_by_isp_for_sinkhole(sinkhole_id, isp, page=page, per_page=per_page)
        return api_response(
            data=result.get('ips', []),
            page=result.get('page'),
            per_page=result.get('per_page'),
            total=result.get('total'),
            total_pages=result.get('total_pages'),
            meta={"sinkhole_id": sinkhole_id, "isp": result.get('isp')},
        )
    except Exception as e:
        return api_response(data=[], success=False, error=str(e), status_code=500)


@app.get('/api/pcaps/set/{sinkhole_id}/domains/{domain:path}/isps')

def get_isps_for_domain_in_set(request: Request, sinkhole_id: int, domain: str, current_user: dict = Depends(require_role('admin', 'user'))):
    """Return the ISPs of IPs that connected to a domain within a sinkhole set."""
    try:
        page     = _query_param(request, 'page', 1, int)
        per_page = _query_param(request, 'per_page', 50, int)
        result   = elastic.get_isps_for_domain_in_sinkhole(sinkhole_id, domain, page=page, per_page=per_page)
        return api_response(
            data=result.get('isps', []),
            page=result.get('page'),
            per_page=result.get('per_page'),
            total=result.get('total'),
            total_pages=result.get('total_pages'),
            meta={"sinkhole_id": sinkhole_id, "domain": result.get('domain')},
        )
    except Exception as e:
        return api_response(data=[], success=False, error=str(e), status_code=500)


# ============= FEEDBACK =============
@app.post('/api/feedback')


async def submit_feedback(
    request: Request,
    current_user: dict = Depends(require_role('admin', 'user')),
):
    form = await request.form()
    name = (form.get('name') or '').strip()
    email = (form.get('email') or '').strip()
    organisation = (form.get('organisation') or '').strip()
    message = (form.get('message') or '').strip()

    if not name or not email or not message:
        return api_response(data=None, success=False, error='name, email and message are required', status_code=400)

    role = request.state.current_user['role']

    try:
        elastic.index_feedback(name, email, organisation, message, role)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)

    return api_response(data={'message': 'Feedback submitted successfully'})


@app.get('/api/feedback')


def get_feedback(current_user: dict = Depends(require_role('admin'))):
    try:
        _es = get_es()
        if not _es:
            return api_response(data=None, success=False, error='Elasticsearch unavailable', status_code=503)
        res = _es.search(
            index=elastic.FEEDBACK_INDEX,
            body={
                "query": {"match_all": {}},
                "sort": [{"submitted_at": {"order": "desc"}}],
                "size": 10000,
            }
        )
        data = [{**hit["_source"], "id": hit["_id"]} for hit in res["hits"]["hits"]]
        return api_response(data=data)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


@app.delete('/api/feedback/{feedback_id}')


def delete_feedback(feedback_id: str, current_user: dict = Depends(require_role('admin'))):
    try:
        _es = get_es()
        if not _es:
            return api_response(data=None, success=False, error='Elasticsearch unavailable', status_code=503)
        _es.delete(index=elastic.FEEDBACK_INDEX, id=feedback_id)
        return api_response(data={'message': f'Feedback {feedback_id} deleted successfully'})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


# ============= CEPH S3 =============
def _s3():
    return boto3.client(
        's3',
        endpoint_url=os.getenv('CEPH_RGW_ENDPOINT', 'http://localhost:7480'),
        aws_access_key_id=os.getenv('RGW_ACCESS_KEY'),
        aws_secret_access_key=os.getenv('RGW_SECRET_KEY'),
        region_name=os.getenv('RGW_REGION', 'us-east-1'),
    )


@app.get('/api/ceph/buckets')


def ceph_list_buckets(current_user: dict = Depends(require_role('admin'))):
    try:
        res = _s3().list_buckets()
        buckets = [{'name': b['Name'], 'created': b['CreationDate'].isoformat()} for b in res.get('Buckets', [])]
        return api_response(data=buckets, total=len(buckets))
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)

@app.post('/api/ceph/buckets')


async def ceph_create_bucket(request: Request, current_user: dict = Depends(require_role('admin'))):
    body = await _request_json(request) or {}
    bucket = body.get('bucket')
    if not bucket:
        return api_response(data=None, success=False, error='bucket is required', status_code=400)
    try:
        _s3().create_bucket(Bucket=bucket)
        return api_response(data={'bucket': bucket})
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)

@app.delete('/api/ceph/buckets/{bucket}')


def ceph_delete_bucket(bucket: str, current_user: dict = Depends(require_role('admin'))):
    try:
        s3 = _s3()
        # Delete all objects first
        objs = s3.list_objects_v2(Bucket=bucket).get('Contents', [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={'Objects': [{'Key': o['Key']} for o in objs]})
        s3.delete_bucket(Bucket=bucket)
        return api_response(data={'bucket': bucket, 'deleted': True})
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)

@app.get('/api/ceph/buckets/{bucket}/objects')


def ceph_list_objects(request: Request, bucket: str, current_user: dict = Depends(require_role('admin'))):
    try:
        prefix = _query_param(request, 'prefix', '', str)
        res = _s3().list_objects_v2(Bucket=bucket, Prefix=prefix)
        objects = [
            {'key': o['Key'], 'size': o['Size'], 'last_modified': o['LastModified'].isoformat()}
            for o in res.get('Contents', [])
        ]
        return api_response(data=objects, total=len(objects))
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)

@app.put('/api/ceph/buckets/{bucket}/objects/{key:path}')


async def ceph_upload_object(request: Request, bucket: str, key: str, current_user: dict = Depends(require_role('admin'))):
    form = await request.form()
    if 'file' not in form:
        return api_response(data=None, success=False, error='file is required', status_code=400)
    try:
        from boto3.s3.transfer import TransferConfig
        f = form['file'].file
        config = TransferConfig(multipart_threshold=50*1024*1024, multipart_chunksize=50*1024*1024, max_concurrency=4)
        _s3().upload_fileobj(f, bucket, key, Config=config)
        return api_response(data={'bucket': bucket, 'key': key})
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)

@app.get('/api/ceph/buckets/{bucket}/objects/{key:path}')


def ceph_download_object(bucket: str, key: str, current_user: dict = Depends(require_role('admin'))):
    try:
        res = _s3().get_object(Bucket=bucket, Key=key)
        return _attachment_response(
            io.BytesIO(res['Body'].read()),
            download_name=key.split('/')[-1],
            as_attachment=True
        )
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)

@app.delete('/api/ceph/buckets/{bucket}/objects/{key:path}')


def ceph_delete_object(bucket: str, key: str, current_user: dict = Depends(require_role('admin'))):
    try:
        _s3().delete_object(Bucket=bucket, Key=key)
        return api_response(data={'bucket': bucket, 'key': key, 'deleted': True})
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e), status_code=500)


# ============= PDF REPORTS =============
PDF_PASSWORDS = {'admin': 'admin@Adm!n', 'user': 'user1@User#'}

def _get_pdf_password(role):
    return PDF_PASSWORDS[role]

def _pdf_response(pdf_bytes, filename):
    return _attachment_response(io.BytesIO(pdf_bytes), mimetype='application/pdf',
                     as_attachment=True, download_name=filename)


def _build_ip_rows_sync(flat_rows):
    packet_map = {r['ip']: r.get('packet_count', 0) for r in flat_rows if r.get('ip')}
    ip_rows = []
    if packet_map:
        _es = get_es()
        if not _es:
            return ip_rows
        res = _es.mget(index=elastic.IP_INTEL_INDEX, body={'ids': list(packet_map.keys())})
        for doc in res['docs']:
            if doc.get('found'):
                row = dict(doc['_source'])
                row['packet_count'] = packet_map.get(row.get('ip'), 0)
                ip_rows.append(row)
        ip_rows.sort(key=lambda r: r.get('packet_count', 0), reverse=True)
        pcaps_map = elastic.get_pcaps_for_ips_bulk(list(packet_map.keys()))
        return _enrich_rows_with_pcap_appearance_data(ip_rows, pcaps_map=pcaps_map)
    return ip_rows


def export_pcap_report_pdf(request: Request, pcap_id: str, report_type: str, report_value: str, current_user: dict = Depends(require_role('admin', 'user'))):
    import urllib.parse
    report_value = urllib.parse.unquote(_query_param(request, 'value', report_value, str))
    if _query_param(request, 'sync', '', str).lower() == 'true':
        from report_pdf import build_pdf
        ip_rows = _build_ip_rows_sync(elastic.get_pcap_report_details(pcap_id, report_type, report_value))
        safe = report_value.replace('/', '_').replace(' ', '_')
        return _pdf_response(build_pdf(title=report_value, subtitle='Report', meta_pairs=[('PCAP ID', pcap_id)], ip_rows=ip_rows, password=_get_pdf_password(current_user['role']), report_type=report_type, report_value=report_value), f'{pcap_id}_{report_type}_{safe}_report.pdf')
    job_id = str(uuid.uuid4())
    celery_client.send_task(
        'tasks.generate_pcap_report_pdf_task',
        args=[job_id, pcap_id, report_type, report_value, _get_pdf_password(current_user['role'])]
    )
    return api_response(data={'job_id': job_id})


def export_report_details_pdf(request: Request, report_type: str, report_value: str, current_user: dict = Depends(require_role('admin', 'user'))):
    import urllib.parse
    report_value = urllib.parse.unquote(_query_param(request, 'value', report_value, str))
    if _query_param(request, 'sync', '', str).lower() == 'true':
        from report_pdf import build_pdf
        ip_rows = _build_ip_rows_sync(elastic.get_report_details(report_type, report_value))
        safe = report_value.replace('/', '_').replace(' ', '_')
        return _pdf_response(build_pdf(title=report_value, subtitle='Report', meta_pairs=[], ip_rows=ip_rows, password=_get_pdf_password(current_user['role']), report_type=report_type, report_value=report_value), f'{report_type}_{safe}_report.pdf')
    job_id = str(uuid.uuid4())
    celery_client.send_task(
        'tasks.generate_report_details_pdf_task',
        args=[job_id, report_type, report_value, _get_pdf_password(current_user['role'])]
    )
    return api_response(data={'job_id': job_id})


@app.get('/api/pcaps/{pcap_id}/export')

def export_pcap_ip_intelligence_pdf(request: Request, pcap_id: str, current_user: dict = Depends(require_role('admin', 'user'))):
    if _query_param(request, 'sync', '', str).lower() == 'true':
        from report_pdf import build_pdf
        meta = elastic.get_dashboard_document(pcap_id)
        if not meta:
            return api_response(data=None, success=False, error=f'No analysis found for {pcap_id}', status_code=404)
        external_ips = elastic.get_external_ips_for_pcap(pcap_id)
        ip_rows = _build_ip_rows_sync(external_ips)
        filename = meta.get('pcap_filename') or meta.get('file_name') or pcap_id
        return _pdf_response(build_pdf(
            title=f'PCAP Report — {filename}',
            subtitle=f'IP Intelligence · PCAP ID: {pcap_id}',
            meta_pairs=[('PCAP ID', pcap_id), ('Filename', filename), ('Total Packets', meta.get('total_packets')), ('Duration (s)', meta.get('duration_seconds')), ('External IPs', len(external_ips)), ('Intel Records', len(ip_rows))],
            ip_rows=ip_rows, password=_get_pdf_password(current_user['role'])
        ), f'{pcap_id}_ip_intelligence.pdf')
    job_id = str(uuid.uuid4())
    celery_client.send_task(
        'tasks.generate_pcap_ip_intelligence_pdf_task',
        args=[job_id, pcap_id, _get_pdf_password(current_user['role'])]
    )
    return api_response(data={'job_id': job_id})


# ============= CLEAN EXPORT ENDPOINTS =============
@app.get('/api/export/country')

def export_country_pdf(request: Request, current_user: dict = Depends(require_role('admin', 'user'))):
    value = _query_param(request, 'value', '', str).strip()
    if not value:
        return api_response(data=None, success=False, error='value query param is required', status_code=400)
    if _query_param(request, 'sync', '', str).lower() == 'true':
        from report_pdf import build_pdf
        ip_rows = _build_ip_rows_sync(elastic.get_report_details('country', value))
        safe = value.replace('/', '_').replace(' ', '_')
        return _pdf_response(build_pdf(title=value, subtitle='Report', meta_pairs=[], ip_rows=ip_rows, password=_get_pdf_password(current_user['role']), report_type='country', report_value=value), f'country_{safe}_report.pdf')
    job_id = str(uuid.uuid4())
    celery_client.send_task(
        'tasks.generate_report_details_pdf_task',
        args=[job_id, 'country', value, _get_pdf_password(current_user['role'])]
    )
    return api_response(data={'job_id': job_id})


@app.get('/api/export/isp')

def export_isp_pdf(request: Request, current_user: dict = Depends(require_role('admin', 'user'))):
    value = _query_param(request, 'value', '', str).strip()
    if not value:
        return api_response(data=None, success=False, error='value query param is required', status_code=400)
    if _query_param(request, 'sync', '', str).lower() == 'true':
        from report_pdf import build_pdf
        ip_rows = _build_ip_rows_sync(elastic.get_report_details('isp', value))
        safe = value.replace('/', '_').replace(' ', '_')
        return _pdf_response(build_pdf(title=value, subtitle='Report', meta_pairs=[], ip_rows=ip_rows, password=_get_pdf_password(current_user['role']), report_type='isp', report_value=value), f'isp_{safe}_report.pdf')
    job_id = str(uuid.uuid4())
    celery_client.send_task(
        'tasks.generate_report_details_pdf_task',
        args=[job_id, 'isp', value, _get_pdf_password(current_user['role'])]
    )
    return api_response(data={'job_id': job_id})


@app.get('/api/export/pcap/{pcap_id}/country')

def export_pcap_country_pdf(request: Request, pcap_id: str, current_user: dict = Depends(require_role('admin', 'user'))):
    value = _query_param(request, 'value', '', str).strip()
    if not value:
        return api_response(data=None, success=False, error='value query param is required', status_code=400)
    if _query_param(request, 'sync', '', str).lower() == 'true':
        from report_pdf import build_pdf
        ip_rows = _build_ip_rows_sync(elastic.get_pcap_report_details(pcap_id, 'country', value))
        safe = value.replace('/', '_').replace(' ', '_')
        return _pdf_response(build_pdf(title=value, subtitle='Report', meta_pairs=[('PCAP ID', pcap_id)], ip_rows=ip_rows, password=_get_pdf_password(current_user['role']), report_type='country', report_value=value), f'{pcap_id}_country_{safe}_report.pdf')
    job_id = str(uuid.uuid4())
    celery_client.send_task(
        'tasks.generate_pcap_report_pdf_task',
        args=[job_id, pcap_id, 'country', value, _get_pdf_password(current_user['role'])]
    )
    return api_response(data={'job_id': job_id})


@app.get('/api/export/pcap/{pcap_id}/isp')

def export_pcap_isp_pdf(request: Request, pcap_id: str, current_user: dict = Depends(require_role('admin', 'user'))):
    value = _query_param(request, 'value', '', str).strip()
    if not value:
        return api_response(data=None, success=False, error='value query param is required', status_code=400)
    if _query_param(request, 'sync', '', str).lower() == 'true':
        from report_pdf import build_pdf
        ip_rows = _build_ip_rows_sync(elastic.get_pcap_report_details(pcap_id, 'isp', value))
        safe = value.replace('/', '_').replace(' ', '_')
        return _pdf_response(build_pdf(title=value, subtitle='Report', meta_pairs=[('PCAP ID', pcap_id)], ip_rows=ip_rows, password=_get_pdf_password(current_user['role']), report_type='isp', report_value=value), f'{pcap_id}_isp_{safe}_report.pdf')
    job_id = str(uuid.uuid4())
    celery_client.send_task(
        'tasks.generate_pcap_report_pdf_task',
        args=[job_id, pcap_id, 'isp', value, _get_pdf_password(current_user['role'])]
    )
    return api_response(data={'job_id': job_id})


# ============= PDF JOB STATUS & DOWNLOAD =============
@app.get('/api/export/status/{job_id}')

def pdf_export_status(job_id: str, current_user: dict = Depends(require_role('admin', 'user'))):
    import redis as redis_lib, time as _time
    r = redis_lib.from_url(os.getenv('REDIS_URL', 'redis://redis:6379/0'))
    raw = r.get(f'pdf_job:{job_id}')
    if not raw:
        return api_response(data=None, success=False, error='Job not found or expired', status_code=404)
    info = json.loads(raw)
    # Detect worker crash: pending for more than 10 minutes
    if info.get('status') == 'pending' and info.get('started_at'):
        if _time.time() - info['started_at'] > 600:
            info['status'] = 'timed_out'
            info['error'] = 'PDF generation timed out — worker may have crashed'
            r.setex(f'pdf_job:{job_id}', 300, json.dumps(info))
    return api_response(data=info)


@app.get('/api/export/download/{job_id}')

def pdf_export_download(job_id: str, current_user: dict = Depends(require_role('admin', 'user'))):
    import redis as redis_lib
    r = redis_lib.from_url(os.getenv('REDIS_URL', 'redis://redis:6379/0'))
    raw = r.get(f'pdf_job:{job_id}')
    if not raw:
        return api_response(data=None, success=False, error='Job not found or expired', status_code=404)
    info = json.loads(raw)
    status = info.get('status')
    if status == 'failed':
        return api_response(data=info, success=False, error=info.get('error', 'PDF generation failed'), status_code=500)
    if status != 'done':
        return api_response(data=info, success=False, error='PDF not ready yet', status_code=202)
    path = os.path.join('/tmp/pdf_jobs', f'{job_id}.pdf')
    if not os.path.exists(path):
        r.delete(f'pdf_job:{job_id}')
        return api_response(data=None, success=False, error='PDF file missing on server', status_code=404)
    filename = info.get('filename', f'{job_id}.pdf')
    buf = io.BytesIO(open(path, 'rb').read())
    try:
        os.remove(path)
    except Exception:
        pass
    r.delete(f'pdf_job:{job_id}')
    return _attachment_response(buf, mimetype='application/pdf', as_attachment=True, download_name=filename)


# ============= MAIN =============
if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=5000)