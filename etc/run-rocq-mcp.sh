#!/usr/bin/env bash
ARGS=$(sed -E -e '/^#/d' -e "s/'([^']*)'//g" -e 's/-arg //g' _RocqProject)
# exec so that MCP client connects directly to rocq-mcp,
# without indirecting thru this shell script.
exec rocq-mcp $ARGS
