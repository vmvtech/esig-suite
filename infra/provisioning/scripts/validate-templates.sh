#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
CONTROL_PLANE_TEMPLATE="$ROOT_DIR/infra/provisioning/template.yaml"
CUSTOMER_TEMPLATE="$ROOT_DIR/infra/provisioning/customer-stack.yaml"
CFN_LINT_VERSION=1.53.3

if [[ -n "${CFN_LINT_BIN:-}" ]]; then
  "$CFN_LINT_BIN" "$CONTROL_PLANE_TEMPLATE" "$CUSTOMER_TEMPLATE"
elif command -v cfn-lint >/dev/null 2>&1; then
  cfn-lint "$CONTROL_PLANE_TEMPLATE" "$CUSTOMER_TEMPLATE"
elif command -v uvx >/dev/null 2>&1; then
  uvx --from "cfn-lint==$CFN_LINT_VERSION" cfn-lint \
    "$CONTROL_PLANE_TEMPLATE" "$CUSTOMER_TEMPLATE"
else
  echo "cfn-lint is required (directly or through uvx)." >&2
  exit 1
fi
