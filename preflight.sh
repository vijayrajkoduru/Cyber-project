#!/usr/bin/env bash
# JSX syntax check via @babel/parser (same parser CRA uses).
# Cached in a named docker volume so subsequent runs are ~3s.
set -e
cd "$(dirname "$0")"

ts=$(date +%Y%m%d-%H%M%S)
mkdir -p .snapshots
cp src/App.js ".snapshots/App.js.$ts"
ls -t .snapshots/App.js.* 2>/dev/null | tail -n +11 | xargs -r rm

if ! docker run --rm \
       -v "$PWD/src":/src:ro \
       -v preflight_npm:/root/.npm \
       node:18-alpine sh -c '
         cd /tmp && npm i --silent --no-fund --no-audit @babel/parser >/dev/null 2>&1
         node -e "
           const fs = require(\"fs\"), parser = require(\"@babel/parser\");
           try {
             parser.parse(fs.readFileSync(\"/src/App.js\",\"utf8\"), {
               sourceType: \"module\",
               plugins: [\"jsx\", \"classProperties\", \"optionalChaining\", \"nullishCoalescingOperator\"]
             });
             console.log(\"✓ syntax OK\");
           } catch (e) {
             console.error(\"✗\", e.message);
             if (e.loc) console.error(\"  → line\", e.loc.line, \"col\", e.loc.column);
             process.exit(1);
           }
         "
       ' 2>&1; then
  echo ""
  echo "Snapshot saved: .snapshots/App.js.$ts"
  echo "Revert:  cp .snapshots/App.js.$ts src/App.js"
  echo "Or git:  git checkout HEAD -- src/App.js"
  exit 1
fi
