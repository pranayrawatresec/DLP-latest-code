'use strict';

// Undefined is preserved by UPDATEs: older consoles cannot switch Bluetooth off.
function validateBluetoothMode(value) {
  if (value === undefined) return { ok: true, value: null };
  if (!['off', 'monitor', 'enforce'].includes(value)) {
    return { ok: false, error: 'bluetoothMode must be off|monitor|enforce' };
  }
  return { ok: true, value };
}

module.exports = { validateBluetoothMode };
