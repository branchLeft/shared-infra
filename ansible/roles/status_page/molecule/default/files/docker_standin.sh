#!/bin/sh
# TEST STAND-IN, not docker. The test has no container engine (ANS-15 forbids
# reaching one), so prepare.yml installs this as `docker` in the instance. It
# records each call and answers the few the role and the compose module make,
# in the shapes the module's source parses. It runs no containers.
state=/var/lib/status_page_standin
case " $* " in
  *" --dry-run "*) log=dryrun.log ;;
  *) log=argv.log ;;
esac
printf '%s\n' "$*" >> "$state/$log"
case " $* " in
  *" compose version "*) printf '{"version":"v2.40.3"}\n' ;;
  *" version "*) printf '{"Client":{"Version":"28.0.0"}}\n' ;;
  *" config "*) ;;
  *" up "*)
    printf '{"id":"Container stand-in-gatus-1","status":"Working","text":"Recreate"}\n' >&2
    printf '{"id":"Container stand-in-gatus-1","status":"Done","text":"Recreated"}\n' >&2
    ;;
  *" ps "*) cat "$state/ps.json" ;;
  *" images "*) printf '[]\n' ;;
  *) printf 'stand-in: call not expected\n' >&2; exit 64 ;;
esac
