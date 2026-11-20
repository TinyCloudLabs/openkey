-- TC-3596: a native approval records which gate let it through, for audit: no
-- passkey was required, the passkey sign-in made for this request covered it, or
-- a passkey assertion bound to the request's revision did. Additive: existing rows
-- take NULL, and the API writes the column only when it approves.
ALTER TABLE "tinycloud_native_request"
  ADD COLUMN "approvalPasskeyMethod" TEXT,
  ADD CONSTRAINT "tinycloud_native_request_approvalPasskeyMethod_check" CHECK (
    "approvalPasskeyMethod" IS NULL
    OR "approvalPasskeyMethod" IN ('NOT_REQUIRED', 'FLOW_PASSKEY', 'REQUEST_PASSKEY')
  );
