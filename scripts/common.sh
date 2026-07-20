#!/usr/bin/env bash
# shared helpers for local harness scripts
POC_JAVA_OPTS=(
  -Djava.net.useSystemProxies=false
  -Dhttp.nonProxyHosts=*
  -Dhttp.proxyHost=
  -Dhttps.proxyHost=
  -Dsun.net.client.defaultConnectTimeout=3000
  -Dsun.net.client.defaultReadTimeout=3000
)
