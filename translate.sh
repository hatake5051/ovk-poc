#!/bin/bash
if [ $1 = 'server' ]; then
  sed -i '' -e 's/browser/node/g' build/utility/runtime/index.js
fi

if [ $2 = 'vm' ]; then
  sed -i '' -e 's|http://localhost:8080|https://ovk.htk.k3.ipv6.mobi|g' build/entrypoint/client.js
fi