-- TC-3442: when an approval needs a passkey assertion bound to the request. Additive; existing rows take the default.
ALTER TABLE "user"
  ADD COLUMN "passkeyApprovalMode" TEXT NOT NULL DEFAULT 'SENSITIVE',
  ADD CONSTRAINT "user_passkey_approval_mode_check"
    CHECK ("passkeyApprovalMode" IN ('ALWAYS', 'SENSITIVE', 'NEVER'));
