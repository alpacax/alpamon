# Body over 2 MiB

Not committed. Generate it from `hosts/ubuntu-default/expected.json`: decode it, append copies of its last `accounts` element until the canonical JSON of the whole object exceeds 2 MiB (2097152 bytes), and send that. The server must answer `413` before parsing. `TestOversizeBody` in `pkg/exposure` builds the same body.
