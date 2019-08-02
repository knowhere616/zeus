#!/bin/bash
#!/bin/bash
rsync -vrzcKl \
  --exclude-from sync.ignore \
  -e "ssh" \
  --rsync-path="sudo rsync" \
  --out-format="[%t]:%o:%f:Last Modified %M" \
  --no-perms \
  --no-owner \
  --no-group \
  --ignore-times \
  . $@

