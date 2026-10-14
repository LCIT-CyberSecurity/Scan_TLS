#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRASHTEST_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_PROJECT="${CRASHTEST_COMPOSE_PROJECT:-${COMPOSE_PROJECT_NAME:-tlsscan-crashtest}}"
COMPOSE_FILE="${CRASHTEST_DIR}/compose.crashtest.yaml"
CA_FILE="${CRASHTEST_DIR}/ldap-certs/ca.crt"
CA_IN_CONTAINER="/tmp/crashtest-ldap-ca.crt"
LDAP_CONTAINER=""
API_CONTAINER=""

fail() {
  printf 'OpenLDAP CrashTest failed: %s\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail 'Docker is required; run this on the integration VM.'
docker version >/dev/null 2>&1 || fail 'Docker Engine is not reachable.'
docker compose version >/dev/null 2>&1 || fail 'Docker Compose is unavailable.'
[[ -r "${CA_FILE}" ]] || fail 'CrashTest LDAP CA is missing; start CrashTest first.'

LDAP_CONTAINER="$(docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}" ps -q openldap)"
[[ -n "${LDAP_CONTAINER}" ]] || fail "No OpenLDAP container found for Compose project ${COMPOSE_PROJECT}."
ldap_health="$(docker inspect -f '{{.State.Health.Status}}' "${LDAP_CONTAINER}" 2>/dev/null || true)"
[[ "${ldap_health}" == healthy ]] || fail "OpenLDAP is not healthy (state: ${ldap_health:-unknown})."

API_CONTAINER="$(docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}" ps -q api)"
[[ -n "${API_CONTAINER}" ]] || fail "No API container found for Compose project ${COMPOSE_PROJECT}."
health="$(docker inspect -f '{{.State.Health.Status}}' "${API_CONTAINER}" 2>/dev/null || true)"
[[ "${health}" == healthy ]] || fail "CrashTest API is not healthy (state: ${health:-unknown})."

cleanup() {
  docker exec "${API_CONTAINER}" rm -f "${CA_IN_CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker cp "${CA_FILE}" "${API_CONTAINER}:${CA_IN_CONTAINER}" >/dev/null
docker exec -i "${API_CONTAINER}" python - <<'PY'
import ast
from pathlib import Path

import httpx


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


seed = ast.parse(Path('/app/tests/crashtest/seed.py').read_text(encoding='utf-8'))
admin_password = next(ast.literal_eval(node.value) for node in ast.walk(seed)
                      if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'ADMIN_FINAL' for target in node.targets))
ldif = Path('/app/tests/crashtest/ldap/bootstrap.ldif').read_text(encoding='utf-8')
ldap_password = next(line.removeprefix('userPassword: ') for line in ldif.splitlines() if line.startswith('userPassword: '))
ca_pem = Path('/tmp/crashtest-ldap-ca.crt').read_text(encoding='utf-8')
base = 'http://127.0.0.1:8000'
admin = httpx.Client(base_url=base, timeout=15)
login = admin.post('/api/auth/login', json={'username': 'admin', 'password': admin_password})
check(login.status_code == 200, 'local fallback admin login failed')
admin.headers['Cookie'] = login.headers['set-cookie'].split(';')[0]
csrf = login.json()['csrf_token']
headers = {'x-csrf-token': csrf}
previous = admin.get('/api/admin/auth')
check(previous.status_code == 200, 'cannot read current authentication configuration')
previous_value = previous.json()['stored']

value = {
    'provider': 'ldap',
    'ldap': {
        'name': 'CrashTest LDAP',
        'server_url': 'ldaps://openldap:636',
        'base_dn': 'ou=people,dc=crashtest,dc=example,dc=com',
        'login_attribute': 'uid',
        'user_filter': '(objectClass=inetOrgPerson)',
        'bind_dn': 'cn=admin,dc=crashtest,dc=example,dc=com',
        'starttls': False,
        'ca_pem': ca_pem,
        'email_attribute': 'mail',
        'name_attribute': 'cn',
        'id_attribute': 'entryUUID',
    },
    'default_role': 'USER',
    'auto_provision': True,
}
try:
    configured = admin.put('/api/admin/auth', json={'value': value}, headers=headers)
    check(configured.status_code == 200, 'LDAP configuration was rejected')
    providers = httpx.get(f'{base}/api/auth/providers', timeout=15).json()
    check(providers.get('ldap') == {'enabled': True, 'name': 'CrashTest LDAP'}, 'LDAP provider was not enabled')

    steps = admin.post('/api/admin/auth/test/ldap', json={'username': 'ldap-user', 'password': ldap_password}, headers=headers)
    check(steps.status_code == 200, 'LDAP diagnostic endpoint failed')
    failed = [step['step'] for step in steps.json() if step.get('status') == 'fail']
    check(not failed, f'LDAP diagnostic steps failed: {", ".join(failed)}')

    user = httpx.Client(base_url=base, timeout=15)
    authenticated = user.post('/api/auth/ldap/login', json={'username': 'ldap-user', 'password': ldap_password})
    check(authenticated.status_code == 200, 'LDAP sign-in failed')
    identity = authenticated.json()['user']
    check(identity.get('role') == 'USER', 'LDAP sign-in assigned an unexpected role')
    check(identity.get('local_account') is False, 'LDAP identity was marked as a local account')
    user.headers['Cookie'] = authenticated.headers['set-cookie'].split(';')[0]
    check(user.get('/api/auth/me').status_code == 200, 'LDAP sign-in did not create a TLS Scan session')

    again = httpx.post(f'{base}/api/auth/ldap/login', json={'username': 'ldap-user', 'password': ldap_password}, timeout=15)
    check(again.status_code == 200, 'LDAP reauthentication failed')
    check(again.json()['user']['id'] == identity['id'] and again.json()['user']['role'] == 'USER',
          'LDAP reauthentication did not preserve the existing identity and role')
    print('local_fallback_admin=PASS')
    print('ldaps_diagnostics=PASS')
    print('ldap_sign_in_and_tls_scan_session=PASS')
    print('identity_and_role_reuse=PASS role=USER')
finally:
    restored = admin.put('/api/admin/auth', json={'value': previous_value}, headers=headers)
    check(restored.status_code == 200, 'could not restore the prior authentication configuration')
PY
