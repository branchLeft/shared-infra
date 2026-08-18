# Caddy with the two modules this edge needs compiled in. Neither ships in the
# official binary, and Caddy has no runtime plugin loading, so a custom build is
# the only way to have either at all.
#
# Every version below is pinned, including the base images by digest: this image
# terminates TLS for every hostname branchLeft serves, and `caddy:2` moving under
# a rebuild would change that with no diff to read.

ARG CADDY_VERSION=2.11.4

FROM caddy:${CADDY_VERSION}-builder-alpine@sha256:c2433c74c0648b47d8a844ff1792661f93996c553687101bbdf89c63a09dccef AS builder

# `caddy-ratelimit` is pinned to a commit rather than a tag on purpose. Its only
# tag, v0.1.0, predates both the removal of the repository's work-in-progress
# notice and the metrics work; the tag is older than the module's own stability
# claim, so it is the wrong thing to depend on.
RUN xcaddy build \
    --with github.com/hslatman/caddy-crowdsec-bouncer/http@v0.14.1 \
    --with github.com/hslatman/caddy-crowdsec-bouncer/appsec@v0.14.1 \
    --with github.com/mholt/caddy-ratelimit@5625512f24f6f59d6f64fb3aafe5eecff0b286db

FROM caddy:${CADDY_VERSION}-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Proves the two modules are actually registered rather than silently absent —
# an xcaddy build that resolved nothing still produces a working Caddy, and the
# first symptom would be a config full of unrecognised directives at deploy time.
RUN caddy list-modules | grep -qx 'http.handlers.rate_limit' \
    && caddy list-modules | grep -qx 'http.handlers.appsec' \
    && caddy list-modules | grep -qx 'http.handlers.crowdsec'
