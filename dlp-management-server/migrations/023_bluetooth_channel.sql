-- Independent Bluetooth mode, delivered alongside the group read policy.
-- Existing deployments remain off; NULL group values inherit Default.
ALTER TABLE read_deny_policy ADD COLUMN bluetooth_mode TEXT NOT NULL DEFAULT 'off'
  CHECK (bluetooth_mode IN ('off', 'monitor', 'enforce'));
ALTER TABLE group_read_deny_policy ADD COLUMN bluetooth_mode TEXT
  CHECK (bluetooth_mode IN ('off', 'monitor', 'enforce'));
