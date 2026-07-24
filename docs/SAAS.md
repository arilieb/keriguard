# KERIGuard SaaS Mode — Design Document

## Overview

KERIGuard currently operates exclusively in **local mode**: a self-hosted registrar handles credential publishing, OOBIs, and credential search; sentinel queries witnesses directly. This document describes extending KERIGuard to support **SaaS mode**, where the healthKERI platform (hkweb) replaces the registrar and sentinel uses the ESSR-authenticated watcher network instead of querying witnesses directly.

The scope covers:
1. A new SaaS configuration path in `keriguard.yaml`
2. Changes to `guardian up` to skip registrar setup in SaaS mode
3. A KERIGuard Registrar API on hkweb that mirrors the open-source registrar repo
4. A SaaS-aware credential loader in sentinel that calls hkweb via ESSR
5. Admin plugin (Locksmith) support for publishing credentials to hkweb via ESSR

---

## Architecture: Local Mode vs SaaS Mode

### Local Mode (current)

```
Locksmith (keriguard admin plugin)
  │ PUT CESR grant bytes
  ▼
Registrar (registrar repo)         ← self-hosted HTTP server
  │ /credential/{said}
  │ /credentials/search?issuer=X
  │ /oobi/{aid}
  ▼
Sentinel (local mode, direct witness queries)
  │ FileWatchingService reads kel/, tel/, cred/
  ▼
Guardian (keriguard) → WireGuard config
```

### SaaS Mode (to build)

```
Locksmith (keriguard admin plugin)
  │ ESSR PUT to /registrar/ (CESR grant bytes)
  ▼
hkweb KERIGuard API (new)           ← ESSR-protected
  │ /registrar/credential/{said}?registry=true&tel=true
  │ /registrar/credentials/search?issuer=X&issuer_sn=N  → 412 if behind
  │ /registrar/oobi/{aid}
  ▼
Sentinel (SaaS mode, ESSR to hkweb, WatchedAdjudicationPoller)
  │ polls /adjudications via ESSR
  │ loads credentials via ESSR (/registrar/credentials/search + /registrar/credential/{said})
  ▼
Guardian (keriguard) → WireGuard config (no registrar peer)
```

---

## Reference Files

### keriguard
| File | Purpose |
|------|---------|
| `/Users/arilieb/healthkeri/keriguard/src/keriguard/core/initializing.py` | `InitializationConfig`, `RegistrarConfig`, `IssuerConfig` — config loading |
| `/Users/arilieb/healthkeri/keriguard/src/keriguard/app/cli/commands/guardian/up.py` | `guardian up` command — creates sentinel, loads OOBIs, writes configs |
| `/Users/arilieb/healthkeri/keriguard/src/keriguard/app/cli/commands/guardian/connect.py` | Processes interface credential file, sets up watchers |
| `/Users/arilieb/healthkeri/keriguard/src/keriguard/app/sentinel/services/cred_service.py` | `CredService` — processes credentials into WireGuard config files |
| `/Users/arilieb/healthkeri/keriguard/src/keriguard/db/basing.py` | `KERIGuardBaser` — LMDB: stores registrar/issuer metadata |
| `/Users/arilieb/healthkeri/keriguard/src/keriguard/app/sentinel/config.py` | `SentinelHandlerConfig` dataclass |
| `/Users/arilieb/healthkeri/keriguard/scripts/data/keriguard.yaml` | Config template (local mode) |

### sentinel
| File | Purpose |
|------|---------|
| `/Users/arilieb/healthkeri/sentinel/src/sentinel/app/sentineling.py` | `setup_local()`, `setup_hk()` — service factory |
| `/Users/arilieb/healthkeri/sentinel/src/sentinel/app/cli/commands/start.py` | CLI: dispatches to `setup_hk` or `setup_local` based on `args.local` |
| `/Users/arilieb/healthkeri/sentinel/src/sentinel/core/watching.py` | `WatchedAdjudicationPoller`, `ObvsSocketListener` — ESSR polling |
| `/Users/arilieb/healthkeri/sentinel/src/sentinel/core/credentialing.py` | `CredentialLoader` — fetches credentials from registrar HTTP |
| `/Users/arilieb/healthkeri/sentinel/src/sentinel/core/initializing.py` | `SentinelConfig` — YAML config read/write |

### hkweb
| File | Purpose |
|------|---------|
| `/Users/arilieb/healthkeri/hkweb/src/hkapi/app/resting.py` | Falcon route registration (`setup_app`) |
| `/Users/arilieb/healthkeri/hkweb/src/hkapi/app/api/credential.py` | `CredentialCollectionEnd`, `CredentialResourceEnd` — existing credential endpoints |
| `/Users/arilieb/healthkeri/hkweb/src/hkapi/app/api/watcher.py` | `AdjudicationCollectionEnd` — existing adjudication endpoint |
| `/Users/arilieb/healthkeri/hkweb/src/hksvc/core/authing.py` | `SignatureValidationComponent` — ESSR auth middleware |
| `/Users/arilieb/healthkeri/hkweb/src/hksvc/core/services/credential_service.py` | `CredentialService` — MongoDB credential storage |
| `/Users/arilieb/healthkeri/hkweb/src/hksvc/core/services/key_event_log_service.py` | `KeyEventLogService`, `Aid` model — KEL and key state |
| `/Users/arilieb/healthkeri/hkweb/src/hksvc/core/services/watcher_service.py` | `WatcherService` — adjudication queries |

### admin plugin
| File | Purpose |
|------|---------|
| `/Users/arilieb/healthkeri/keriguard-plugin/plugins/admin/src/keriguard_admin/plugin.py` | `KERIGuardAdminPlugin` — vault open/close lifecycle |
| `/Users/arilieb/healthkeri/keriguard-plugin/plugins/admin/src/keriguard_admin/settings.py` | `KERIGuardSettingsPage` — UI for registrar URL, registry, export dir |
| `/Users/arilieb/healthkeri/keriguard-plugin/plugins/admin/src/keriguard_admin/db/basing.py` | `KERIGuardSettings` LMDB record — stores settings |
| `/Users/arilieb/healthkeri/keriguard-plugin/plugins/admin/src/keriguard_admin/machines/issue.py` | `IssueInterfaceCredentialPage` — issues credential and pushes to registrar |
| `/Users/arilieb/healthkeri/keriguard-plugin/plugins/admin/src/keriguard_admin/core/remoting.py` | `push_credential_to_registrar()` — plain HTTP PUT to registrar |

### ESSR / kept
| File | Purpose |
|------|---------|
| `/Users/arilieb/healthkeri/kept/src/kept/hk/essring.py` | `APIClient` — ESSR client (used by sentinel's setup_hk) |
| `/Users/arilieb/healthkeri/kept/src/kept/hk/configing.py` | `HealthKERIConfig.get_instance()` — reads env vars for platform URLs |
| `/Users/arilieb/healthkeri/whisper/src/whisper/core/remoting.py` | Reference pattern: how a Locksmith plugin calls hkweb via ESSR |

---

## Key Code Snippets

### How `setup_hk` creates ESSR and `WatchedAdjudicationPoller`
`sentinel/src/sentinel/app/sentineling.py:115–201`
```python
config = HealthKERIConfig.get_instance()
essr = APIClient(url=config.protected_url, root=config.api_aid, hby=hby, hab=hab)
await sync_server_key_state(name, alias, base, bran, essr)

poller = WatchedAdjudicationPoller(
    hby=hby, rgy=rgy, essr=essr, db=db,
    poll_interval=15.0, export_dir=export_dir,
    registrar_url=registrar_url,   # ← this becomes essr-based in SaaS mode
)
```

### How `WatchedAdjudicationPoller` triggers credential loading
`sentinel/src/sentinel/core/watching.py:530–537`
```python
if self.credential_loader:
    asyncio.create_task(
        self.credential_loader.search_for_credentials(watched_aid, remote_sn)
    )
```

### How `CredentialLoader` calls the registrar search
`sentinel/src/sentinel/core/credentialing.py:86`
```python
url = f"{self.registrar_url}/credentials/search?issuer={pre}&issuer_sn={current_sn}"
# Returns 200 {"credentials": [saids]} or 412 if registrar not caught up
```

### How `guardian up` writes sentinel config (local mode today)
`keriguard/src/keriguard/app/cli/commands/guardian/up.py:192–210`
```python
sentinel_config.local = True          # ← must become False in SaaS mode
sentinel_config.registrar.url = config.registrar.url
...
load_oobi(hby=keriguard_hby, oobi=config.registrar.oobi, alias="registrar")
load_oobi(hby=keriguard_hby, oobi=config.registrar.keriguard.oobi, alias="registrar-keriguard")
```

### How CredService conditionally adds registrar peer
`keriguard/src/keriguard/app/sentinel/services/cred_service.py:81–92`
```python
registrar = self.kgb.get_registrar()
if registrar and registrar.endpoint:   # ← already guards; SaaS: registrar.endpoint will be None
    manager.add_peer_to_config(config, allowed_ips=registrar.ipaddress,
                               endpoint=registrar.endpoint, ...)
```

### Whisper plugin ESSR pattern (reference for admin plugin)
`whisper/src/whisper/core/remoting.py:22–26, 197–254`
```python
def _get_essr(app):
    return app.vault.plugin_state.get("whisper", {}).get("essr")

async def upload_issued_credential(app, credential_said, schema, issuer, recipient):
    essr = _get_essr(app)
    files = {
        'acdc': ('output.bin', bytes(acdc), 'application/octet-stream'),
        'doc': ('data.json', json.dumps(doc), 'application/json'),
    }
    response = await essr.request(path="/issued-credentials", method="POST", files=files)
```

### Existing hkweb credential collection (POST already exists)
`hkweb/src/hkapi/app/api/credential.py:72–149` — accepts multipart `doc` + `acdc` fields.  
`hkweb/src/hkapi/app/resting.py:160–164` — `/credentials` and `/credentials/{said}` are already mounted.

---

## Build Plan

---

### Phase 1: SaaS Config in keriguard.yaml + KeriguardConfig

**What**: Add a `local` top-level flag and optional `server` section to `keriguard.yaml`. Update `InitializationConfig` to parse these. The `registrar` section becomes optional when `local: false`.

**Files to modify**:
- `keriguard/src/keriguard/core/initializing.py`
- `keriguard/scripts/data/keriguard.yaml` (add SaaS template example in comments)

**New config schema**:
```yaml
# SaaS mode
local: false
server:
  code: "ABC..."         # server auth code (used by sentinel up)

issuer:
  aid: "EI6-..."
  oobi: "http://witness.example.com/oobi/EI6-.../witness"
```

**Changes to `initializing.py`**:

1. Add `ServerConfig` class with `.code` property.
2. Add `local` property to `InitializationConfig` (defaults `True` for backwards compat).
3. Add `server` property returning optional `ServerConfig`.
4. Make `KeriguardConfig.registrar` tolerant of missing `registrar` key — return empty `RegistrarConfig` instead of raising.

**Manual test**: Write a `keriguard-saas.yaml` with `local: false` and no `registrar` section. Confirm `KeriguardConfig.load()` parses cleanly, `config.local == False`, `config.server.code == "ABC..."`, `config.registrar.aid == ""`.

---

### Phase 2: `guardian up` SaaS Branch

**What**: When `config.local is False`, skip registrar OOBI loading, skip registrar peer storage, and write `sentinel_config.local = False`.

**Files to modify**:
- `keriguard/src/keriguard/app/cli/commands/guardian/up.py`

**Key logic change** (lines 168–222):

```python
if config.local:
    # current behavior: load registrar OOBIs, validate, store registrar in KGBaser
    load_oobi(hby=keriguard_hby, oobi=config.registrar.oobi, alias="registrar")
    load_oobi(hby=keriguard_hby, oobi=config.registrar.keriguard.oobi, alias="registrar-keriguard")
    load_oobi(hby=sentinel_hby, oobi=config.registrar.oobi, alias="registrar")
    load_oobi(hby=sentinel_hby, oobi=config.registrar.keriguard.oobi, alias="registrar-keriguard")
    if (config.registrar.aid not in keriguard_hby.kevers
            or config.registrar.keriguard.aid not in keriguard_hby.kevers
            or config.issuer.aid not in keriguard_hby.kevers):
        raise ConfigurationError(...)
    kgb.set_registrar(
        aid=config.registrar.aid,
        keriguard_aid=config.registrar.keriguard.aid,
        oobi=config.registrar.oobi,
        keriguard_oobi=config.registrar.keriguard.oobi,
        url=config.registrar.url,
        ipaddress=config.registrar.keriguard.ipaddress,
        endpoint=config.registrar.keriguard.endpoint,
    )
else:
    # SaaS mode: only load issuer OOBI; no registrar peer
    if config.issuer.aid not in keriguard_hby.kevers:
        raise ConfigurationError(...)
    # kgb.set_registrar() NOT called — registrar.endpoint stays None

# Sentinel config: reflect local flag
sentinel_config.local = config.local      # False in SaaS mode → setup_hk() runs
sentinel_config.registrar.url = config.registrar.url if config.local else None
```

The sentinel config written with `local: false` causes `sentinel start` to call `setup_hk()` which already handles ESSR-based watching via `WatchedAdjudicationPoller`.

**Manual test**:
1. Run `keriguard guardian up --config keriguard-saas.yaml --name keriguard --alias keriguard --sentinel-config-path /tmp/test-sentinel.yaml`
2. Confirm no registrar OOBI is fetched.
3. Open `/tmp/test-sentinel.yaml` and verify `local: false`.
4. Confirm `sudo wg show` returns no peer for registrar after `guardian connect` runs.

---

### Phase 3: hkweb KERIGuard Registrar API

**What**: Add a new set of Falcon endpoints under `/registrar/` that mirror the open-source registrar's HTTP API. All endpoints are authenticated by the existing `SignatureValidationComponent` ESSR middleware.

**Files to create/modify**:
- `hkweb/src/hkapi/app/api/keriguard.py` ← **new file**
- `hkweb/src/hksvc/core/services/keriguard_service.py` ← **new file** (or extend `credential_service.py`)
- `hkweb/src/hkapi/app/resting.py` — register new routes in `setup_app()`

**New endpoints** (all ESSR-protected via existing middleware):

```
PUT  /registrar/                                   Parse IPEX grant, store credential
GET  /registrar/credential/{said}                  Return CESR stream (application/cesr)
     ?registry=true  include registry TEL
     ?tel=true       include credential TEL
GET  /registrar/credentials/search                 Search credentials by issuer
     ?issuer={aid}&issuer_sn={int}                 412 if adjudication SN < issuer_sn
GET  /registrar/oobi/{aid}                         Return OOBI CESR for a watched AID
```

**`hkapi/app/api/keriguard.py`** skeleton:

```python
import falcon
from hksvc.core.services.keriguard_service import KERIGuardService

class KERIGuardRegistrarEnd:
    def __init__(self, keriguardSvc: KERIGuardService):
        self.service = keriguardSvc

    def on_put(self, req, resp):
        """Parse IPEX grant bytes (mirrors registrar PUT /)"""
        data = req.bounded_stream.read()
        self.service.parse_grant(data)
        resp.status = falcon.HTTP_204

class KERIGuardCredentialEnd:
    def on_get(self, req, resp, said):
        """Return CESR stream for a credential (mirrors registrar GET /credential/{said})"""
        registry = req.get_param_as_bool("registry", default=False)
        tel = req.get_param_as_bool("tel", default=False)
        try:
            out = self.service.get_credential_cesr(said, registry=registry, tel=tel)
        except NotFoundError:
            raise falcon.HTTPNotFound()
        resp.status = falcon.HTTP_200
        resp.content_type = "application/cesr"
        resp.data = out

class KERIGuardCredentialSearchEnd:
    def on_get(self, req, resp):
        """Search credentials by issuer; 412 if keystate behind issuer_sn"""
        issuer = req.get_param("issuer", required=True)
        issuer_sn = req.get_param_as_int("issuer_sn", required=True)
        try:
            saids = self.service.search_credentials(issuer, issuer_sn)
        except KeystateBehindError:
            raise falcon.HTTPPreconditionFailed(
                description="hkweb keystate not caught up to issuer_sn"
            )
        resp.status = falcon.HTTP_200
        resp.media = {"credentials": saids}

class KERIGuardOOBIEnd:
    def on_get(self, req, resp, aid):
        """Return CESR OOBI for a watched identifier"""
        try:
            oobi_bytes = self.service.get_oobi_cesr(aid)
        except NotFoundError:
            raise falcon.HTTPNotFound()
        resp.status = falcon.HTTP_200
        resp.content_type = "application/cesr"
        resp.data = oobi_bytes
```

**`hksvc/core/services/keriguard_service.py`** key methods:

```python
class KERIGuardService:
    def __init__(self, hby, rgy, tvy, parser, watcherSvc, kelSvc):
        ...

    def parse_grant(self, data: bytes):
        """Parse raw CESR grant bytes (like registrar's PUT /)"""
        self.parser.parse(data)
        self.parser.exc.processEscrow()
        self.rgy.tvy.processEscrows()
        self.verifier.processEscrows()

    def get_credential_cesr(self, said, registry=False, tel=False) -> bytes:
        """Return full CESR stream — mirrors registrar's output_cred()"""
        # Uses existing CredentialService.get_credential_stream() or
        # reconstructs from regy.reger similar to registrar apiing.py
        ...

    def search_credentials(self, issuer_aid: str, issuer_sn: int) -> list[str]:
        """
        Return SAIDs of credentials issued by issuer_aid.
        Raises KeystateBehindError if watcher adjudication SN < issuer_sn.
        """
        # 1. Get latest adjudication for issuer_aid from watcher_service
        adj = self.watcherSvc.get_latest_adjudication(issuer_aid)
        if adj is None or adj.sn < issuer_sn:
            raise KeystateBehindError(f"hkweb at sn={adj.sn if adj else 0}, need {issuer_sn}")

        # 2. Query credentials from MongoDB by issuer
        creds = Credential.objects(issuer=issuer_aid)
        return [c.said for c in creds]

    def get_oobi_cesr(self, aid: str) -> bytes:
        """Return OOBI CESR for a watched AID (mirrors registrar get_oobi)"""
        # Use hby.kevers to find AID, then replyToOobi
        ...
```

**Route registration** in `hkapi/app/resting.py` inside `setup_app()`:
```python
from hkapi.app.api.keriguard import (
    KERIGuardRegistrarEnd, KERIGuardCredentialEnd,
    KERIGuardCredentialSearchEnd, KERIGuardOOBIEnd
)
keriguardSvc = KERIGuardService(hby=hby, rgy=rgy, tvy=tvy, parser=parser,
                                 watcherSvc=watcherSvc, kelSvc=kelSvc)

app.add_route("/registrar/", KERIGuardRegistrarEnd(keriguardSvc))
app.add_route("/registrar/credential/{said}", KERIGuardCredentialEnd(keriguardSvc))
app.add_route("/registrar/credentials/search", KERIGuardCredentialSearchEnd(keriguardSvc))
app.add_route("/registrar/oobi/{aid}", KERIGuardOOBIEnd(keriguardSvc))
```

**Note on `get_credential_cesr`**: The existing `CredentialService.get_credential_stream()` at `hkweb/src/hksvc/core/services/credential_service.py:360` returns ACDC+TEL bytes but does not include the registry TEL header that `CredentialLoader._load_credential` expects (`?registry=true`). Verify against the registrar's `output_cred()` in `registrar/src/registrar/core/apiing.py:331` to ensure byte-for-byte compatibility.

**Manual test (Phase 3)**:
1. Start hkweb. Issue a credential to a watched AID in MongoDB.
2. Test via an ESSR client (or `sentinel up` with SaaS config):
   - `PUT /registrar/` with a valid IPEX grant CESR → expect 204
   - `GET /registrar/credentials/search?issuer=X&issuer_sn=0` → expect `{"credentials": [...]}`
   - `GET /registrar/credentials/search?issuer=X&issuer_sn=9999` → expect 412
   - `GET /registrar/credential/{said}?registry=true&tel=true` → expect CESR bytes
   - `GET /registrar/oobi/{watched_aid}` → expect CESR OOBI

---

### Phase 4: SaaS Credential Loader in Sentinel

**What**: Add `SaaSCredentialLoader` that makes ESSR calls to hkweb's `/registrar/` API instead of plain HTTP calls to the registrar. Wire it into `WatchedAdjudicationPoller` when `setup_hk()` is invoked.

**Files to modify**:
- `sentinel/src/sentinel/core/credentialing.py`
- `sentinel/src/sentinel/core/watching.py`
- `sentinel/src/sentinel/app/sentineling.py`

**`SaaSCredentialLoader`** in `credentialing.py`:

```python
class SaaSCredentialLoader:
    """
    SaaS-mode credential loader: uses ESSR to talk to hkweb's /registrar/ API.
    Mirrors the interface of CredentialLoader but uses essr instead of registrar_url.
    """

    def __init__(self, hby, hab, rgy, export_dir, essr):
        self.hby = hby
        self.hab = hab
        self.rgy = rgy
        self.verifier = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)
        self.psr = parsing.Parser(kvy=self.hby.kvy, tvy=self.rgy.tvy, vry=self.verifier)
        self.export_dir = export_dir
        self.essr = essr

    async def search_for_credentials(self, pre, current_sn):
        base_delay = 5.0
        max_attempts = 6
        path = f"/registrar/credentials/search?issuer={pre}&issuer_sn={current_sn}"

        for attempt in range(1, max_attempts + 1):
            try:
                response = await self.essr.request(path=path, method="GET")
                if response.status_code == 200:
                    saids = response.json().get("credentials", [])
                    await asyncio.gather(*[self._load_credential(said) for said in saids])
                    self.psr.kvy.processEscrows()
                    self.rgy.tvy.processEscrows()
                    self.verifier.processEscrows()
                    await asyncio.gather(*[self._save_credential(said) for said in saids])
                    return
                elif response.status_code == 412:
                    logger.info("SaaSCredentialLoader: hkweb not caught up, retrying")
                else:
                    logger.error(f"SaaSCredentialLoader: unexpected {response.status_code}")
                    return
            except Exception as e:
                logger.error(f"SaaSCredentialLoader: attempt {attempt} error: {e}")

            if attempt < max_attempts:
                await asyncio.sleep(base_delay * (2 ** (attempt - 1)))

    async def _load_credential(self, said):
        if self.rgy.reger.creds.get(keys=(said,)) is not None:
            return
        path = f"/registrar/credential/{said}?registry=true&tel=true"
        try:
            response = await self.essr.request(path=path, method="GET")
            if response.status_code == 200:
                self.psr.parse(response.content)
        except Exception as e:
            logger.error(f"SaaSCredentialLoader: error loading {said}: {e}")

    async def _save_credential(self, said):
        # identical to CredentialLoader._save_credential
        ...
```

**Wire into `WatchedAdjudicationPoller`** (`watching.py:321–368`):

Change constructor to accept either `registrar_url` (plain HTTP) or `saas_loader` (ESSR):
```python
def __init__(self, hby, rgy, essr, db, poll_interval, export_dir,
             registrar_url=None, saas_loader=None):
    ...
    if saas_loader is not None:
        self.credential_loader = saas_loader
    elif registrar_url:
        self.credential_loader = CredentialLoader(hby, self.essr.hab, rgy, export_dir, registrar_url)
    else:
        self.credential_loader = None
```

**Wire into `setup_hk()`** (`sentineling.py:162–170`):

```python
saas_loader = SaaSCredentialLoader(
    hby=hby, hab=hab, rgy=rgy, export_dir=export_dir, essr=essr
)
poller = WatchedAdjudicationPoller(
    hby=hby, rgy=rgy, essr=essr, db=db,
    poll_interval=15.0, export_dir=export_dir,
    saas_loader=saas_loader,              # ← SaaS; no registrar_url
)
```

**Manual test (Phase 4)**:
1. Start hkweb with at least one published credential in MongoDB.
2. Run `sentinel start --config /tmp/test-sentinel.yaml` (the config written by Phase 2 with `local: false`).
3. Add a watched identifier (the issuer) via `sentinel watcher add`.
4. Confirm sentinel logs: `SaaSCredentialLoader: Successfully queried for issuer X credentials`.
5. Confirm the credential `.cesr` file appears in the sentinel export directory.

---

### Phase 5: Admin Plugin SaaS Publish Path

**What**: Add a `publish_mode` setting to the admin plugin and, when in SaaS mode, publish credentials via ESSR to `/registrar/` instead of via plain HTTP PUT to the registrar.

**Files to modify**:
- `keriguard-plugin/plugins/admin/src/keriguard_admin/db/basing.py` — add `publish_mode` to `KERIGuardSettings`
- `keriguard-plugin/plugins/admin/src/keriguard_admin/settings.py` — add dropdown UI
- `keriguard-plugin/plugins/admin/src/keriguard_admin/plugin.py` — initialize ESSR on vault open
- `keriguard-plugin/plugins/admin/src/keriguard_admin/core/remoting.py` — add `push_credential_via_essr()`
- `keriguard-plugin/plugins/admin/src/keriguard_admin/machines/issue.py` — branch on `publish_mode`

#### Step 5a: Add `publish_mode` to settings LMDB record

In `db/basing.py`, add `publish_mode: str` (values: `"registrar"` | `"hkweb"`) to the `KERIGuardSettings` dataclass/MappingRecord.

#### Step 5b: Add publish mode dropdown to settings UI

In `settings.py`, add a `FloatingLabelComboBox("Publish Mode")` with options `["registrar", "hkweb"]`. Wire to `_save_settings(publish_mode=...)`.

#### Step 5c: Initialize ESSR on vault open

In `plugin.py` `on_vault_opened()`:

```python
def on_vault_opened(self, vault: "Vault") -> None:
    self._db = KERIGuardBaser(name=vault.hby.name, reopen=True)
    _, account = next(self._db.keriguardAccounts.getItemIter(), (None, None))
    _, team = next(self._db.keriguardTeams.getItemIter(), (None, None))

    # Initialize ESSR if healthKERI account exists
    essr = None
    if account:
        try:
            from kept.hk.configing import HealthKERIConfig
            from kept.hk.essring import APIClient
            config = HealthKERIConfig.get_instance()
            hab = vault.hby.habByName(account.alias)   # use the HK account hab
            if hab:
                essr = APIClient(
                    url=config.protected_url,
                    root=config.api_aid,
                    hby=vault.hby,
                    hab=hab,
                )
        except Exception as e:
            logger.warning(f"KERIGuard: could not init ESSR: {e}")

    vault.plugin_state["keriguard"] = {
        "account": account,
        "team": team,
        "db": self._db,
        "essr": essr,      # ← new
    }
```

#### Step 5d: Add ESSR push function in `remoting.py`

```python
async def push_credential_via_essr(
    grant: bytes,
    essr,
    introduction_bytes: bytes | None = None,
) -> None:
    """Push CESR grant bytes to hkweb's /registrar/ endpoint via ESSR."""
    response = await essr.request(
        path="/registrar/",
        method="PUT",
        data=grant,
        headers={"Content-Type": "application/cesr"},
        timeout=30,
    )
    if response is None or response.status_code not in (200, 204):
        raise RuntimeError(
            f"hkweb /registrar/ returned {response.status_code if response else 'None'}"
        )

    if introduction_bytes:
        response = await essr.request(
            path="/registrar/",
            method="PUT",
            data=introduction_bytes,
            headers={"Content-Type": "application/cesr"},
            timeout=30,
        )
```

#### Step 5e: Branch on `publish_mode` in `machines/issue.py`

In `_on_issue_clicked()` (around lines 361–378), replace the current push logic:

```python
kg_db = self.app.vault.plugin_state.get("keriguard", {}).get("db")
settings = kg_db.keriguardSettings.get(keys=("settings",)) if kg_db else None
essr = self.app.vault.plugin_state.get("keriguard", {}).get("essr")

grant = issuer.grant(creder.said, recipient_aid)
grant_bytes = bytes(grant)

introduction_bytes = None
if recipient_oobi:
    exn, end = exchanging.exchange(route="/introduction", payload=..., ...)
    introduction_bytes = bytes(hab.endorse(serder=exn, last=False, pipelined=False))

publish_mode = settings.publish_mode if settings else "registrar"

if publish_mode == "hkweb" and essr:
    from ..core.remoting import push_credential_via_essr
    await push_credential_via_essr(grant_bytes, essr, introduction_bytes)
elif publish_mode == "registrar" and settings and settings.registrar_url:
    from ..core.remoting import push_credential_to_registrar, push_introduction_to_registrar
    await push_credential_to_registrar(grant_bytes, settings.registrar_url)
    if introduction_bytes:
        await push_introduction_to_registrar(introduction_bytes, settings.registrar_url)
```

**Manual test (Phase 5)**:
1. Open Locksmith vault that has a healthKERI account.
2. Set KERIGuard publish mode to "hkweb" in the settings page.
3. Issue an interface credential from the Machines → Issue page.
4. Confirm hkweb logs show the PUT to `/registrar/` received.
5. Call `GET /registrar/credentials/search?issuer=X&issuer_sn=0` via ESSR; confirm credential SAID appears.

---

### Phase 6: End-to-End SaaS Flow Validation

This phase describes the complete SaaS-mode flow. The section is organized into three parts: a map of every keystore and identifier involved, the step-by-step provisioning sequence, and the verification procedure.

---

#### 6.1 Keystores and Identifiers

SaaS mode involves **three physical keystores** and **five distinct identifiers**. Understanding which identifier lives where, and what role it plays in authentication, is essential to reasoning about the flow.

---

##### Keystore A — Locksmith Vault (admin machine)

The admin's Locksmith vault is a standard Habery (`vault.hby`). It is the only keystore that lives on the admin's machine. It can contain any number of identifiers; the following three have specific roles in the SaaS flow.

| Identifier | How created | Role |
|---|---|---|
| **Account identifier** | Admin creates in vault, selects during healthKERI account creation (`POST /accounts`) | Signs all ESSR requests from the admin plugin to hkweb. hkweb validates via `AccountService.get_account(signer)`. **Cannot be rotated** — hkweb stores it as a primary key with no rotation endpoint (`account_service.py`). |
| **Issuer identifier** | Admin creates in vault separately | Issues WireGuard interface and connection ACDCs. Its AID and OOBI go in `keriguard.yaml issuer:`. Should be **different from the account identifier** so it can be independently rotated without destroying the hkweb account. The admin plugin's issuance page (`machines/issue.py`) lets the user choose any vault identifier as the issuer. |
| **Server delegator identifier** | Admin creates in vault, uploads to hkweb | Must be uploaded to hkweb *before* creating a server auth code. Specified as `delegator` in the server auth code request (`POST /account/teams/servers/auth-codes`). The keriguard peer identifier is created as a KERI delegated identifier under this AID. |

The admin plugin's ESSR client is always bound to the **account identifier**, not the issuer (`plugin.py:89`):
```python
hab = vault.hby.habByName(account.alias)   # account identifier
essr = APIClient(url=..., hab=hab)
```
Credential pushes to `/registrar/` are therefore signed by the account identifier.

---

##### Keystore B — Keriguard server keystore (server machine, name: `keriguard`)

Created by `sentinel up` on the server machine. Contains:

| Identifier | How created | Role |
|---|---|---|
| **Keriguard peer identifier** (`keriguard` alias) | `sentinel up` with `delpre=<server-delegator-aid>` — **delegated** | THE WireGuard peer AID. Its KERI public key is used to derive the WireGuard public key. Receives interface credentials from the issuer. Registered on hkweb as `TeamServer.delegated_aid`. |
| **Watcher identifier** (`keriguard-watcher` alias) | `sentinel up`, non-transferable | Internal watcher role; used by `Oobiery` and local watching infrastructure. |

The keriguard peer identifier **must be delegated** (`delpre` set). `sync_server_key_state` (`sentinel/core/eventing.py:19`) checks for the AES (Authorizer Event Seal) and fetches the delegator's KEL from hkweb to confirm delegation. A non-delegated keriguard AID will cause this function to fail.

---

##### Keystore C — Keriguard sentinel keystore (server machine, name: `keriguard-sentinel`)

Created by `sentinel up` on the server machine. Contains:

| Identifier | How created | Role |
|---|---|---|
| **Sentinel identifier** (`keriguard-sentinel` alias) | `sentinel up`, transferable, provisioned with witnesses by hkweb | Signs all ESSR requests from the running sentinel to hkweb. Registered on hkweb as **`TeamServer.aid`** (the primary server AID). hkweb validates via `TeamService.get_server_by_aid(signer)`. |

`setup_hk` (`sentineling.py:116`) opens this keystore and builds the ESSR client from the sentinel identifier:
```python
hby = habbing.Habery(name=name, ...)          # "keriguard-sentinel" keystore
hab = hby.habByName(alias)                     # sentinel identifier
essr = APIClient(url=..., hab=hab)             # ESSR signed by sentinel AID
```

---

##### Summary table

| Identifier | Keystore | Signs requests to hkweb as | hkweb lookup |
|---|---|---|---|
| Account identifier | Locksmith vault | `Account` | `AccountService.get_account` |
| Issuer identifier | Locksmith vault | (not used for ESSR directly) | n/a |
| Server delegator | Locksmith vault | (not used for ESSR directly) | n/a |
| Keriguard peer | `keriguard` | (no direct ESSR) | `TeamServer.delegated_aid` |
| Sentinel | `keriguard-sentinel` | `TeamServer` (primary) | `TeamService.get_server_by_aid` |

---

#### 6.2 Provisioning Sequence

**Prerequisites**:
- hkweb running with Phase 3 endpoints
- Locksmith with Phase 5 plugin changes
- keriguard with Phases 1–2 changes
- sentinel with Phase 4 changes

---

##### Step A — Locksmith: create server auth code

In Locksmith, the admin must have:
1. A healthKERI account and team (account identifier uploaded during account creation)
2. The **server delegator identifier** uploaded to hkweb (`PUT /identifiers/<aid>`)
3. The **issuer identifier** uploaded to hkweb (so the sentinel can watch it)

Then in Locksmith → healthKERI → Servers:
- Select the server delegator identifier
- Click **Provision** → hkweb creates a `TeamServer` record with `status = PENDING_REGISTRATION` and returns an auth code string

Copy the auth code. It has the form `<24-char-lookup><24-char-secret>`.

---

##### Step B — Server machine: `sentinel up`

This is the **first command run on the server machine**. It creates both server keystores and registers the server on hkweb.

```bash
sentinel up \
  --name keriguard \
  --alias keriguard \
  --auth-key "<server-auth-code-from-locksmith>" \
  --delegator "<server-delegator-aid>"
```

What this does (`sentinel/app/cli/commands/up.py`):
1. Creates keystore B (`keriguard`) with the **keriguard peer identifier** (`delpre=<delegator>`)
2. Creates keystore C (`keriguard-sentinel`) with the **sentinel identifier**
3. Creates the watcher identifier in keystore B
4. Calls `POST /account/teams/servers` (unauthenticated, uses auth code):
   - `aid = sentinel_hab.pre` ← sentinel identifier becomes `TeamServer.aid`
   - `delegated_aid = server_hab.pre` ← keriguard peer becomes `TeamServer.delegated_aid`
   - `server_auth_code = <code>` ← consumed to look up and validate the `TeamServer` record
5. hkweb assigns witnesses; sentinel up rotates the sentinel identifier to include them
6. `PUT /account/teams/servers/<sentinel_aid>` finalizes the KEL with witnesses
7. `TeamServer.status` → `PENDING_APPROVAL`

After this step the server prints:
```
Delegated Server keriguard: <keriguard-peer-aid>
healthKERI Account keriguard-sentinel: <sentinel-aid>
Watcher keriguard-watcher: <watcher-aid>
```

---

##### Step C — Locksmith: approve the server (admin performs delegation IXN)

In Locksmith → Servers, the pending server appears. The admin clicks **Approve**:

1. Locksmith parses the keriguard peer's `dip` (delegation inception) from the stored `delegated_kel`
2. Calls `hab.interact(data=[anchor])` on the **server delegator identifier** — emitting an **IXN** that anchors the keriguard peer's inception as a delegation seal
3. The admin completes witness authentication for the IXN
4. The post-IXN delegator KEL is submitted to `PUT /servers/<delegated_aid>` on hkweb
5. hkweb confirms the delegation and sets `TeamServer.status = LIVE`

A background path also exists: palantir's `process_server_delegation` (`palantir/app/adjudication.py:147`) detects the delegator's key state advance via watcher queries and confirms independently.

> **Known gap**: `_on_auth_codes_entered` in `locksmith/ui/vault/healthKERI/servers/approve_server.py:234` is currently a stub — it logs but does not yet call the PUT endpoint. Until this is wired, the palantir watcher background path is the only working confirmation route.

---

##### Step D — Server machine: `kg guardian up`

Once the server keystores exist (Step B), initialize the guardian:

```bash
cat > /opt/healthkeri/config/keriguard.yaml <<EOF
local: false
server:
  code: "<server-auth-code>"    # stored for reference; not yet consumed by guardian up
issuer:
  aid: "<issuer-aid>"
  oobi: "<issuer-oobi-from-witness>"
EOF

kg guardian up \
  --name keriguard \
  --alias keriguard \
  -c /opt/healthkeri/config/keriguard.yaml \
  --sentinel-config-path /opt/healthkeri/config/keriguard-sentinel.yaml
```

What this does (`keriguard/app/cli/commands/guardian/up.py`):
1. Opens keystore B (`keriguard`) — requires the keriguard peer identifier to already exist
2. Creates keystore C's sentinel identifier if absent (but `sentinel up` already created it)
3. Resolves the issuer OOBI into both keystores B and C
4. Writes `keriguard-sentinel.yaml` with `name: keriguard-sentinel`, `alias: keriguard-sentinel`, `local: false`
5. Stores `Issuer(aid, oobi)` in `KERIGuardBaser` (keystore B's LMDB)
6. Prints the keriguard peer AID and OOBI — give this OOBI to the admin in Locksmith

Outputs:
```
KERIGuard AID: <keriguard-peer-aid>
KERIGuard OOBI: https://<witness>/oobi/<keriguard-peer-aid>/witness
```

> **Note**: `keriguard.yaml server.code` is provided by the operator as documentation/reference. It is the auth code consumed by the separate `sentinel up` step (Step B); `guardian up` does not read it. The two commands are intentionally separate steps.

---

##### Step E — Locksmith: OOBI the keriguard peer, issue credentials

In Locksmith:
1. Resolve the keriguard peer OOBI from Step D output (adds keriguard peer AID as a contact)
2. Set publish mode to **hkweb** in KERIGuard → Settings
3. Issue an **interface credential** to the keriguard peer AID using the issuer identifier
4. Issue a **connection credential** linking peers

Both credentials are PUTed via ESSR to hkweb `/registrar/` (signed by the account identifier).

---

##### Step F — Server machine: start sentinel

```bash
sudo supervisorctl start keriguard_sentinel
# or: sentinel start --config /opt/healthkeri/config/keriguard-sentinel.yaml
```

`setup_hk` (`sentineling.py`) runs:
1. Opens keystore C (`name="keriguard-sentinel"`) — sentinel identifier
2. Builds ESSR client authenticated as the sentinel identifier
3. `sync_server_key_state(server_name="keriguard", ...)` opens keystore B, verifies the keriguard peer's key state from hkweb
4. Creates `SaaSCredentialLoader` (ESSR-based, calls `/registrar/credentials/search` and `/registrar/credential/<said>`)
5. Creates `WatchedAdjudicationPoller` (polls `/adjudications` for issuer KEL advances)
6. On each adjudication event: calls `SaaSCredentialLoader.search_for_credentials(issuer_aid, sn)` → downloads credentials via ESSR → exports `.cesr` files to the sentinel export directory

---

##### Step G — Start guardian, connect interface

```bash
# Guardian reads exported .cesr files and writes WireGuard config
sudo kg guardian start \
  --name keriguard \
  --alias keriguard \
  --sentinel-aid <sentinel-aid> \
  --sentinel-export-dir /usr/local/var/sentinel/keriguard \
  --config-dir /etc/wireguard

# Or use guardian connect for manual .cesr processing:
kg guardian connect \
  --name keriguard \
  --alias keriguard \
  --export-dir /etc/wireguard \
  --file /path/to/<interface-cred>.cesr
```

---

#### 6.3 Verification

```bash
# 1. Confirm no registrar peer in the WireGuard config
cat /etc/wireguard/wg0.conf
# Expected: [Interface] section present, no [Peer] for the registrar

# 2. Confirm interface is up (Linux)
sudo wg show wg0
# Expected: interface with listening port, peers from connection credentials only

# 3. Confirm sentinel is polling hkweb
# Sentinel logs should show:
#   SaaSCredentialLoader: queried credentials for issuer <aid>

# 4. Confirm credential .cesr file was exported
ls /usr/local/var/sentinel/keriguard/
# Expected: <interface-cred-said>.cesr and <connection-cred-said>.cesr
```

**Expected WireGuard state**: Interface is up with no registrar peer — only peers from connection credentials.

---

#### 6.4 Open Items

| Item | Location | Description |
|---|---|---|
| `_on_auth_codes_entered` stub | `locksmith/.../servers/approve_server.py:234` | Needs to call `PUT /servers/<delegated_aid>` with the post-IXN delegator KEL to confirm server status = LIVE via the direct path; palantir watcher is the only working confirmation path until this is wired |
| `sentinel up` creates delegated keriguard AID | `sentinel/.../commands/up.py:124` | Meeting notes say **do not** create a delegated keriguard identifier; `sentinel up` should be updated to not create the server identifier with `delpre`, and `sync_server_key_state` updated to handle non-delegated keriguard AIDs |
| Account vs issuer identifier guidance | Locksmith onboarding | Operators should create a **separate** issuer identifier from their account identifier — the account AID cannot be rotated on hkweb, while the issuer AID needs independent rotation capability |

---

## Appendix: `HealthKERIConfig` Env Vars (Dev Localhost Override)

`kept/src/kept/hk/configing.py` reads env vars for all URLs. For local dev:
```bash
export HEALTHKERI_PROTECTED_URL="http://localhost:5623"
export HEALTHKERI_API_AID="<hkweb-api-aid>"
export HEALTHKERI_API_OOBI="http://localhost:5642/oobi/<hkweb-api-aid>/controller"
```

No changes needed — `setup_hk()` in sentineling.py already calls `HealthKERIConfig.get_instance()` which reads these.

---

## Summary of Files Changed

| Repo | File                                       | Change |
|------|--------------------------------------------|--------|
| keriguard | `core/initializing.py`                     | Add `local`, `server`/`ServerConfig` to `InitializationConfig` |
| keriguard | `app/cli/commands/guardian/up.py`          | Branch on `config.local` for registrar OOBI load + sentinel config |
| sentinel | `core/credentialing.py`                    | Add `SaaSCredentialLoader` class |
| sentinel | `core/watching.py`                         | `WatchedAdjudicationPoller`: accept `saas_loader` param |
| sentinel | `app/sentineling.py`                       | `setup_hk()`: create and pass `SaaSCredentialLoader`; use `name` directly as sentinel keystore name (not `f"{name}-sentinel"`) |
| hkweb | `hkapi/app/api/registrar.py`               | **NEW**: Falcon endpoint classes for `/registrar/` API |
| hkweb | `hksvc/core/services/keriguard_service.py` | **NEW**: `KERIGuardService` with `parse_grant`, `get_credential_cesr`, `search_credentials`, `get_oobi_cesr` |
| hkweb | `hkapi/app/resting.py`                     | Mount `/registrar/` routes in `setup_app()` |
| keriguard-plugin | `db/basing.py`                             | Add `publish_mode` to `KERIGuardSettings` |
| keriguard-plugin | `settings.py`                              | Add publish mode dropdown |
| keriguard-plugin | `plugin.py`                                | Initialize ESSR client on vault open |
| keriguard-plugin | `core/remoting.py`                         | Add `push_credential_via_essr()` |
| keriguard-plugin | `machines/issue.py`                        | Branch on `publish_mode` for credential push |