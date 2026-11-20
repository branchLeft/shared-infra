# `render.ts` notes (the tenant edge)

CMT-3 pointer target for `hetzner/edge-t/render.ts`. Update this doc, not a long comment
block, when any of the following changes.

## The tenant profile

edge-t is the tenants project's web edge. It runs the same Compose stack shape as the
estate's edge (Caddy and CrowdSec, one unit `branchleft-compose@edge`, one pin) and is
delivered by the same role, `ansible/roles/edge_stack`, selected by
`edge_stack_profile: tenant`. This directory is that profile's source of truth, as
`hetzner/edge/stack/` is the estate's. The two differ in four ways, each on purpose:

1. **No hostname is written into any file.** The estate's files name the registry's
   hostnames. A tenant's name is data (ISSUE branchLeft/workspace#1802), so this
   profile's renderer takes no registry and no hostname. The three Ghost-specific
   CrowdSec files are rendered with the `EVERY_HOST` scope
   (`hetzner/edge/render.md`, "Host scope of the Ghost files"). `render.test.ts` scans every
   rendered and every committed file for every name the estate registry serves or
   redirects, and for the estate's domain, and fails on one.
2. **One catch-all and no site.** The Caddyfile has the same global options and probe
   listeners as the estate's, a metrics listener, and one block on `:80` that answers
   every request no tenant block claims with 503 (the throttle and the bouncer in front,
   no AppSec, which has nothing to inspect on a refused request). With no tenant block
   the edge therefore answers 503 for every name and serves nothing. Tenant blocks and
   on-demand certificates are #1802 and #3823; the catch-all is what an unregistered
   name keeps getting after they land. No `:443` block is rendered, so a TLS handshake for
   a name with no certificate fails and nothing is issued for it.
3. **Fewer CrowdSec files.** The Nextcloud profile and the verified-session whitelist are
   the estate's and have no tenant counterpart yet: nothing on this edge is Nextcloud, and
   no site here verifies sessions with the edge. Compose does not mount a `parsers`
   directory for the same reason.
4. **This host's address and name.** The metrics ports are published on
   `TENANTS_HOST_IPS.edgeT`, and CrowdSec's hostname is `edge-t`.

The posture is spelled out in `TENANT_POSTURE`, with the estate's values today, so a
posture change on one edge does not move the other.

## What is held equal to the estate's, and how

- The CrowdSec image line of `stack/compose.yml` equals the estate's, so a bump of one
  that is not made to the other fails here. That is why the tenant stack has no
  Dependabot entry or hub-pin check of its own.
- The meaningful lines of `stack/crowdsec/config.yaml.local` equal the estate's.
- The bytes the estate renderer makes without a hostname (the acquisition files, the
  ban ladder, the watch-only list) are reused, under this profile's banner. The banner
  swap refuses a file that does not begin with the estate's banner.
- The CrowdSec pin is the only image held equal to the estate's. The two media-cache images
  are the tenant stack's own and have their own Dependabot entry.

## The media address

Readers fetch uploaded media from one address of our own, never from the object store.
The address is a hostname under the platform domain; like every tenant name it is data, so
no file here holds it. `media.ts` renders everything else. A request takes this path:

1. **Caddy, `(tenant_media)`.** Throttle (zone `media_per_ip`, 1200 requests a minute per
   address, because a page loads many images) and the bouncer first. Then, in this order:
   a method other than GET or HEAD is 405; **any query string is 400** (so no
   `?versionId=`, no `?list-type=`, no sub-resource); a `..` segment, plain or encoded, is
   404; an active content extension (the list Ghost's own routes refuse) is 403; a path
   that is not `/<folder>/<object>` is 404. The folder is the tenant's opaque prefix.
   `map` then looks the folder up in the register's map; **a folder the map does not hold,
   or one that names a shard this file does not know, is 404**, and the cache is reachable
   only inside that known-shard handle. The cache is told the shard by the `Host` it is
   sent (`<shard>.media-shard.invalid`). Cookies and credentials are dropped, and every
   answer carries `nosniff` and `Content-Security-Policy: default-src 'none'; sandbox`.
2. **`media-cache` (nginx).** One cache for all shards, keyed by host and raw request path
   (so two spellings of one path cannot share an entry, and one shard's object is never
   served for another's). It collapses concurrent misses (`proxy_cache_lock`), serves a
   stale copy when the shard errors, and fetches whole objects (the client's `Range` is
   dropped upstream and answered from the cache). It sets no lifetime of its own: what is
   stored, and for how long, is what the shard listener says in `X-Accel-Expires` and
   `Cache-Control`. A response with no lifetime is not stored.
3. **The shard listener (Caddy, port 18080, server `media_shard`).** One block per shard,
   and the only thing that talks to that shard's bucket: path-style, the bucket named in
   the block, the query replaced by an empty one. 2xx and 304 are stored (browsers one day,
   the edge seven); 403 and 404 (the store says 403 for a missing object) become a 404
   stored for thirty seconds; **429 and 503 (SlowDown) become a 503 with `Retry-After` and
   `Cache-Control: no-store`, never stored**; anything else is a 502, not stored. A
   catch-all block answers 404 to a host no shard owns, because Caddy answers an unmatched
   host with an empty 200 and the cache would keep it.

### What the host supplies

Both are written by the reconciler that reads the tenant register, into
`/etc/branchleft/edge-media/`, which Compose mounts read-only at `/etc/caddy-media`. Both
are empty until a tenant exists, and the Caddyfile loads with the directory empty.

- `*.caddy`: the media address, as `<hostname> { import tenant_media }`.
- `folders/*.map`: one `<folder> <shard>` pair per line. The folder is the tenant's opaque
  prefix. The reconciler must write only values it generated (a line is Caddyfile text).

### Shards

`MEDIA_SHARDS` in `media.ts` is the list of shared buckets (name, S3 endpoint, bucket). It
is empty until the buckets exist, and with none every media request is 404. A shard's name
is what the register records for a folder; it identifies no tenant.

### Metrics, and the 750 a second

The provider allows 750 requests a second per source address and, separately, per bucket;
neither can be raised, and this edge is one source address.

- Requests to the cache: `nginx_http_requests_total` (port 9113 on edge-t's private
  address; it also counts the exporter's own scrape, one request per scrape interval).
- Upstream requests per shard, which is the rate the bucket sees:
  `caddy_http_requests_total{server="media_shard",host="<shard>.media-shard.invalid"}`
  (port 9091). The catch-all's host is `_other`.
- Hit ratio: `1 - sum(rate(shard requests)) / rate(cache requests)`.
- The source-address budget is the sum over shards, not any one of them.

### Cache size

`max_size=4g` and `inactive=30d` in the Compose file's inline nginx configuration. The
size is a bound on edge-t's disk, to be revisited with that host's disk. The cache holds
files under `/var/cache/nginx/media` named by the hash of the key, so a purge by folder is
not possible: erasing a tenant empties the whole cache.

### Held to the real programs

Run on stock Caddy 2.11.9 and nginx 1.30.6 against a stand-in bucket over plain HTTP,
through the rendered snippet and shard blocks less the throttle, the bouncer and the log
(the stock image has neither module): a second fetch and a HEAD are cache hits and the bucket saw one
request; an unknown folder, a folder mapped to an unknown shard, a query string, a listing
path, a version link, a dot segment (plain and encoded), a POST and an `.svg` are each
refused before the bucket is asked; a 503 from the bucket reaches the reader as a 503 with
`Retry-After` and the next fetch, once the bucket recovers, is a miss that succeeds; a
cached object is still served while the bucket answers 503; a range request is answered
206 from the cache with no `Range` reaching the bucket.
