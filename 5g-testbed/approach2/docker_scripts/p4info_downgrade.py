#!/usr/bin/env python3
"""Strip P4Runtime fields that postdate ONOS 2.2.2 from a p4info text proto.

The committed p4-code artifacts were produced by an older p4c. Recompiling with
a current p4c (the p4lang/p4c image) emits three things that ONOS 2.2.2's
P4Info protobuf does not know:

  * a leading '# proto-file:' / '# proto-message:' comment pair
  * 'initial_default_action { ... }' blocks
  * 'has_initial_entries: true'

Text-format protobuf parsing is strict about unknown fields, so ONOS fails the
whole pipeconf registration with 'pipeconf ... not registered' and the device
never leaves CONNECTION_SETUP. Removing them yields a p4info the older parser
accepts; the stripped fields only restate the 'const entries' already compiled
into the bmv2 JSON, so nothing is lost at runtime.

Usage: p4info_downgrade.py <in.p4info.txt> <out.p4info.txt>
"""
import sys

DROP_BLOCKS = ('initial_default_action',)
DROP_LINES = ('has_initial_entries:',)
DROP_COMMENTS = ('# proto-file:', '# proto-message:')


def downgrade(text):
    out, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if any(stripped.startswith(c) for c in DROP_COMMENTS):
            i += 1
            continue
        if any(stripped.startswith(d) for d in DROP_LINES):
            i += 1
            continue

        # Skip a whole block, tracking nested braces (arguments { ... }).
        if any(stripped.startswith(b) and stripped.endswith('{') for b in DROP_BLOCKS):
            depth = 0
            while i < len(lines):
                depth += lines[i].count('{') - lines[i].count('}')
                i += 1
                if depth <= 0:
                    break
            continue

        out.append(line)
        i += 1

    # Collapse the blank line the comment header leaves behind.
    while out and not out[0].strip():
        out.pop(0)
    return '\n'.join(out) + '\n'


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        result = downgrade(f.read())
    with open(sys.argv[2], 'w') as f:
        f.write(result)
    print("wrote %s" % sys.argv[2])
