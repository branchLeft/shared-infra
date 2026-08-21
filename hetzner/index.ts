import { network, subnet } from './network';
import { verifyEstateProject } from './projectGuard';

// Deliberately not re-exported. `./network` constructs the network and its
// subnet at module scope, so importing this file constructs them — a stack
// that wanted only the host pattern would find a network in its own state.
// The host pattern itself (`Host`, `firewalls`, `cloudInit`, `addressPlan`)
// no longer lives in this directory at all: consumers depend on the
// published `@branchleft/hetzner-host` package instead; see README.md.

/**
 * Refuses the whole program if `hcloud:token` addresses the mail project.
 *
 * This project is the more dangerous of the two to get wrong. Its state is
 * empty before its first apply in the estate project, so a mail-project token
 * plans a clean create — and would put a second network named `platform`,
 * carrying the estate's own CIDR, inside the project mx1 lives in.
 */
export const estateProjectVerified = verifyEstateProject();

export const networkId = network.id;
export const networkName = network.name;
export const networkIpRange = network.ipRange;
export const subnetIpRange = subnet.ipRange;
export const subnetGateway = subnet.gateway;
