# slot_image_textfile

Writes one gauge per tenant stack on an app host: the image digest the stack's pin file names.
A root timer runs a typed Python program every five minutes. It reads each
`/etc/branchleft/<stack>.image.env` that `branchleft_deploy.py` writes, and replaces one
`branchleft_slot_image.prom` atomically in the node_exporter textfile directory:

    branchleft_slot_image_info{stack="<stack>",digest="sha256:<hex>"} 1

## What it takes, changes and refuses

- Takes no input. Its paths are internal (`vars/`), and tests hold them equal to node_exporter's.
- Installs the program at `/usr/local/sbin/branchleft-slot-image-textfile`, a service and a timer
  under `/etc/systemd/system/`, and creates the textfile directory with node_exporter's owner and mode.
- A pin that is not exactly one `IMAGE=<name>@sha256:<64 hex>` line is refused: its stack gets no
  series, the refusal names the file and not the value, and the service exits 1. Valid stacks are
  still exported.
- Refuses a stack file name that does not match the deploy program's rule, a symlink, and a file
  over 4 KiB.

## What it does not do

- It does not read the newest attested image or compare the two. The drift alert is a separate
  change.
- It does not run on a host by SSH from an agent. The timer on the host reads the files.
- Check mode does not enable the timer (a stated skip, ANS-10).

## Tests

- `tests/unit/test_slot_image_textfile.py` runs the program on temporary directories and checks the
  refusal rule, the output shape, the atomic write, the 0644 mode, and that the unit, the program's
  defaults, this role's vars and node_exporter's vars name the same locations.
- `molecule/default` installs the role on a systemd container, writes one valid and one tag pin,
  runs the writer and asserts the gauge. Run through the harness only.
