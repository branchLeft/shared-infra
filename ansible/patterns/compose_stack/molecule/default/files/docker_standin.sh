#!/bin/sh
# TEST STAND-IN, not docker. The test has no container engine (ANS-15 forbids
# reaching one), so prepare.yml installs this as `docker` in the instance. It
# records each call and answers the few the role and the compose module make,
# in the shapes the module's source parses. It runs no containers.
# Three files in the state directory switch its behaviour: config_fails makes
# the compose file validator refuse, up_fails makes a real `up` fail, and
# compose_version sets the version `compose version` reports.
state=/var/lib/compose_stack_standin
case " $* " in
  *" --dry-run "*) log=dryrun.log ;;
  *) log=argv.log ;;
esac
printf '%s\n' "$*" >> "$state/$log"
# The variables Compose is given for this call, one line per call: the verbatim
# checks read the image value and the env files from here. "unset" is printed when
# a variable is not in the environment, so an empty value and no value differ.
printf 'IMAGE=%s COMPOSE_ENV_FILES=%s\n' "${IMAGE-unset}" "${COMPOSE_ENV_FILES-unset}" >> "$state/env.log"
case " $* " in
  *" compose version "*)
    version=v2.40.3
    [ ! -e "$state/compose_version" ] || version=$(cat "$state/compose_version")
    printf '{"version":"%s"}\n' "$version"
    ;;
  *" version "*) printf '{"Client":{"Version":"28.0.0"}}\n' ;;
  *" config "*) [ ! -e "$state/config_fails" ] || { printf 'invalid compose file\n' >&2; exit 1; } ;;
  *" up "*)
    if [ "$log" = argv.log ] && [ -e "$state/up_fails" ]; then
      printf 'stand-in: the image could not be pulled\n' >&2
      exit 1
    fi
    printf '{"id":"Container stand-in-app-1","status":"Working","text":"Recreate"}\n' >&2
    printf '{"id":"Container stand-in-app-1","status":"Done","text":"Recreated"}\n' >&2
    ;;
  *" ps "*) cat "$state/ps.json" ;;
  *" images "*) printf '[]\n' ;;
  *) printf 'stand-in: call not expected\n' >&2; exit 64 ;;
esac
