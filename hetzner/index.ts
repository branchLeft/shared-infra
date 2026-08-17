import { network, subnet } from './network';

// Deliberately not re-exported. `./network` constructs the network and its
// subnet at module scope, so importing this file constructs them — a stack
// that wanted only the host pattern would find a network in its own state.
// Consumers import `./host`, `./firewalls`, `./cloudInit` and `./addressPlan`
// directly; see README.md.

export const networkId = network.id;
export const networkName = network.name;
export const networkIpRange = network.ipRange;
export const subnetIpRange = subnet.ipRange;
export const subnetGateway = subnet.gateway;
