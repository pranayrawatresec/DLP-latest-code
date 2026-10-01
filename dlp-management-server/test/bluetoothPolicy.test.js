'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { validateBluetoothMode } = require('../lib/bluetoothPolicy');
const { policyJson, POLICY_FALLBACK } = require('../lib/groupPolicy');

test('legacy updates preserve Bluetooth mode rather than turning it off', () => {
  assert.deepEqual(validateBluetoothMode(undefined), { ok: true, value: null });
});

test('only explicit supported modes can be saved', () => {
  for (const mode of ['off', 'monitor', 'enforce']) {
    assert.deepEqual(validateBluetoothMode(mode), { ok: true, value: mode });
  }
  for (const mode of [null, true, 1, {}, [], '', 'block', 'ENFORCE']) {
    assert.equal(validateBluetoothMode(mode).ok, false);
  }
});

test('wire policy preserves independent Bluetooth and generic read modes', () => {
  assert.equal(policyJson(POLICY_FALLBACK).bluetoothMode, 'off');
  const wire = policyJson({ ...POLICY_FALLBACK, bluetooth_mode: 'enforce' });
  assert.equal(wire.mode, 'off');
  assert.equal(wire.bluetoothMode, 'enforce');
});
