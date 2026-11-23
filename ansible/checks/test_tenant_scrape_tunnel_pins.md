# test_tenant_scrape_tunnel_pins.py: the tenant scrape tunnel's addresses and ports against their other homes

The `tenant_scrape_tunnel` role keeps its constants in `vars/main.yml`: the three tenant exporters'
addresses, the exporter port, the address the scraper host listens on, and the local port each
exporter is reached on. Each has another home that decides it, and this test holds the two equal:

- the destinations are `TENANTS_HOST_IPS` and the bind address is `HOST_IPS.edge1`, both read from
  `hetzner-host/addressPlan.ts`, their one home (the destination names are the `TENANTS_HOST_IPS` names in
  lower case: `dbT1` is `dbt1`);
- the target port is `NODE_EXPORTER_PORT` of `hetzner/monitoring/render.ts`;
- each local port is the `localPort` of the same host's row in `TENANT_TUNNEL_TARGETS` of
  `hetzner/monitoring/tenantTunnel.ts`, which is what the Prometheus configuration scrapes, and that file's
  bind is `HOST_IPS.edge1`;
- no local port is another destination's, a `*_PORT` constant of `render.ts`, a port published by the
  monitoring or the edge `compose.yml`, or a `*_port` of `owner_vars/edge1.yml`. This is the Python half of the
  collision test in `tenantTunnel.test.ts`;
- edge1 and edge-t each apply the role exactly once, as a plain `role:` entry with no `when`, `vars` or
  `tags`, and `checks/host_roles` lists it for both;
- no path under the role, and no path written in a task, template, variable or the unit, holds the account's
  name, so the name is not spread over the file system.

The control of the control: the address plan, the tunnel rows and the published ports must read as more than
nothing, or every pin above would pass on an empty parse. Each pin runs red on a copy of the files it reads with
one thing broken, and green on the copy left alone. What the test does not see: whether a listed port is free on
the running host, which only the owner's apply shows.
