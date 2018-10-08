/**
 * @license Copyright 2017 Google Inc. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
'use strict';

const UnusedImages =
    require('../../../audits/byte-efficiency/offscreen-images.js');
const NetworkNode = require('../../../lib/dependency-graph/network-node');
const CPUNode = require('../../../lib/dependency-graph/cpu-node');
const assert = require('assert');
const LHError = require('../../../lib/lh-error');

/* eslint-env jest */
function generateRecord(resourceSizeInKb, startTime = 0, mimeType = 'image/png') {
  return {
    mimeType,
    startTime, // DevTools timestamp which is in seconds
    resourceSize: resourceSizeInKb * 1024,
  };
}

function generateSize(width, height, prefix = 'client') {
  const size = {};
  size[`${prefix}Width`] = width;
  size[`${prefix}Height`] = height;
  return size;
}

function generateImage(size, coords, networkRecord, src = 'https://google.com/logo.png') {
  Object.assign(networkRecord || {}, {url: src});

  const x = coords[0];
  const y = coords[1];

  const clientRect = {
    top: y,
    bottom: y + size.clientHeight,
    left: x,
    right: x + size.clientWidth,
  };
  const image = {src, networkRecord, clientRect};
  Object.assign(image, size);
  return image;
}

function generateInteractiveFunc(desiredTimeInSeconds) {
  return () => Promise.resolve({
    timestamp: desiredTimeInSeconds * 1000000,
  });
}

function generateInteractiveFuncError() {
  return () => Promise.reject(
    new LHError(LHError.errors.NO_TTI_NETWORK_IDLE_PERIOD)
  );
}

function generateTraceOfTab(desiredTimeInSeconds) {
  return () => Promise.resolve({
    timestamps: {
      traceEnd: desiredTimeInSeconds * 1000000,
    },
  });
}

describe('OffscreenImages audit', () => {
  let context;
  const DEFAULT_DIMENSIONS = {innerWidth: 1920, innerHeight: 1080};

  beforeEach(() => {
    context = {settings: {throttlingMethod: 'devtools'}};
  });

  it('handles images without network record', () => {
    return UnusedImages.audit_({
      ViewportDimensions: DEFAULT_DIMENSIONS,
      ImageUsage: [
        generateImage(generateSize(100, 100), [0, 0]),
      ],
      traces: {},
      devtoolsLogs: {},
      requestInteractive: generateInteractiveFunc(2),
    }, [], context).then(auditResult => {
      assert.equal(auditResult.items.length, 0);
    });
  });

  it('does not find used images', () => {
    const urlB = 'https://google.com/logo2.png';
    const urlC = 'data:image/jpeg;base64,foobar';
    return UnusedImages.audit_({
      ViewportDimensions: DEFAULT_DIMENSIONS,
      ImageUsage: [
        generateImage(generateSize(200, 200), [0, 0], generateRecord(100)),
        generateImage(generateSize(100, 100), [0, 1080], generateRecord(100), urlB),
        generateImage(generateSize(400, 400), [1720, 1080], generateRecord(3), urlC),
      ],
      traces: {},
      devtoolsLogs: {},
      requestInteractive: generateInteractiveFunc(2),
    }, [], context).then(auditResult => {
      assert.equal(auditResult.items.length, 0);
    });
  });

  it('finds unused images', () => {
    const url = s => `https://google.com/logo${s}.png`;
    return UnusedImages.audit_({
      ViewportDimensions: DEFAULT_DIMENSIONS,
      ImageUsage: [
        // offscreen to the right
        generateImage(generateSize(200, 200), [3000, 0], generateRecord(100)),
        // offscreen to the bottom
        generateImage(generateSize(100, 100), [0, 2000], generateRecord(100), url('B')),
        // offscreen to the top-left
        generateImage(generateSize(100, 100), [-2000, -1000], generateRecord(100), url('C')),
        // offscreen to the bottom-right
        generateImage(generateSize(100, 100), [3000, 2000], generateRecord(100), url('D')),
        // half offscreen to the top, should not warn
        generateImage(generateSize(1000, 1000), [0, -500], generateRecord(100), url('E')),
      ],
      traces: {},
      devtoolsLogs: {},
      requestInteractive: generateInteractiveFunc(2),
    }, [], context).then(auditResult => {
      assert.equal(auditResult.items.length, 4);
    });
  });

  it('finds images with 0 area', () => {
    return UnusedImages.audit_({
      ViewportDimensions: DEFAULT_DIMENSIONS,
      ImageUsage: [
        generateImage(generateSize(0, 0), [0, 0], generateRecord(100)),
      ],
      traces: {},
      devtoolsLogs: {},
      requestInteractive: generateInteractiveFunc(2),
    }, [], context).then(auditResult => {
      assert.equal(auditResult.items.length, 1);
      assert.equal(auditResult.items[0].wastedBytes, 100 * 1024);
    });
  });

  it('de-dupes images', () => {
    const urlB = 'https://google.com/logo2.png';
    return UnusedImages.audit_({
      ViewportDimensions: DEFAULT_DIMENSIONS,
      ImageUsage: [
        generateImage(generateSize(50, 50), [0, 0], generateRecord(50)),
        generateImage(generateSize(1000, 1000), [1000, 1000], generateRecord(50)),
        generateImage(generateSize(50, 50), [0, 1500], generateRecord(200), urlB),
        generateImage(generateSize(400, 400), [0, 1500], generateRecord(90), urlB),
      ],
      traces: {},
      devtoolsLogs: {},
      requestInteractive: generateInteractiveFunc(2),
    }, [], context).then(auditResult => {
      assert.equal(auditResult.items.length, 1);
    });
  });

  it('disregards images loaded after TTI', () => {
    return UnusedImages.audit_({
      ViewportDimensions: DEFAULT_DIMENSIONS,
      ImageUsage: [
        // offscreen to the right
        generateImage(generateSize(200, 200), [3000, 0], generateRecord(100, 3)),
      ],
      traces: {},
      devtoolsLogs: {},
      requestInteractive: generateInteractiveFunc(2),
    }, [], context, [], context).then(auditResult => {
      assert.equal(auditResult.items.length, 0);
    });
  });

  it('disregards images loaded after Trace End when interactive throws error', () => {
    return UnusedImages.audit_({
      ViewportDimensions: DEFAULT_DIMENSIONS,
      ImageUsage: [
        // offscreen to the right
        generateImage(generateSize(200, 200), [3000, 0], generateRecord(100, 3)),
      ],
      traces: {},
      devtoolsLogs: {},
      requestInteractive: generateInteractiveFuncError(),
      requestTraceOfTab: generateTraceOfTab(2),
    }, [], context, [], context).then(auditResult => {
      assert.equal(auditResult.items.length, 0);
    });
  });

  it('finds images loaded before Trace End when TTI when interactive throws error', () => {
    return UnusedImages.audit_({
      ViewportDimensions: DEFAULT_DIMENSIONS,
      ImageUsage: [
        // offscreen to the right
        generateImage(generateSize(100, 100), [0, 2000], generateRecord(100)),
      ],
      traces: {},
      devtoolsLogs: {},
      requestInteractive: generateInteractiveFuncError(),
      requestTraceOfTab: generateTraceOfTab(2),
    }, [], context, [], context).then(auditResult => {
      assert.equal(auditResult.items.length, 1);
    });
  });

  it('disregards images loaded after last long task (Lantern)', () => {
    context = {settings: {throttlingMethod: 'simulate'}};
    const recordA = {url: 'a', resourceSize: 100 * 1024, requestId: 'a'};
    const recordB = {url: 'b', resourceSize: 100 * 1024, requestId: 'b'};

    const networkA = new NetworkNode(recordA);
    const networkB = new NetworkNode(recordB);
    const cpu = new CPUNode({}, []);
    const timings = new Map([
      [networkA, {startTime: 1000}],
      [networkB, {startTime: 2000}],
      [cpu, {startTime: 1975, endTime: 2025, duration: 50}],
    ]);

    return UnusedImages.audit_({
      ViewportDimensions: DEFAULT_DIMENSIONS,
      ImageUsage: [
        generateImage(generateSize(0, 0), [0, 0], recordA, recordA.url),
        generateImage(generateSize(200, 200), [3000, 0], recordB, recordB.url),
      ],
      traces: {},
      devtoolsLogs: {},
      requestInteractive: async () => ({pessimisticEstimate: {nodeTimings: timings}}),
    }, [], context, [], context).then(auditResult => {
      assert.equal(auditResult.items.length, 1);
      assert.equal(auditResult.items[0].url, 'a');
    });
  });

  it('finds images loaded before last long task (Lantern)', () => {
    context = {settings: {throttlingMethod: 'simulate'}};
    const recordA = {url: 'a', resourceSize: 100 * 1024, requestId: 'a'};
    const recordB = {url: 'b', resourceSize: 100 * 1024, requestId: 'b'};

    const networkA = new NetworkNode(recordA);
    const networkB = new NetworkNode(recordB);
    const cpu = new CPUNode({}, []);
    const timings = new Map([
      [networkA, {startTime: 1000}],
      [networkB, {startTime: 1500}],
      [cpu, {startTime: 1975, endTime: 2025, duration: 50}],
    ]);

    return UnusedImages.audit_({
      ViewportDimensions: DEFAULT_DIMENSIONS,
      ImageUsage: [
        generateImage(generateSize(0, 0), [0, 0], recordA, recordA.url),
        generateImage(generateSize(200, 200), [3000, 0], recordB, recordB.url),
      ],
      traces: {},
      devtoolsLogs: {},
      requestInteractive: async () => ({pessimisticEstimate: {nodeTimings: timings}}),
      requestTraceOfTab: generateTraceOfTab(2),
    }, [], context, [], context).then(auditResult => {
      assert.equal(auditResult.items.length, 2);
      assert.equal(auditResult.items[0].url, 'a');
      assert.equal(auditResult.items[1].url, 'b');
    });
  });

  it('rethrow error when interactive throws error in Lantern', async () => {
    context = {settings: {throttlingMethod: 'simulate'}};
    try {
      await UnusedImages.audit_({
        ViewportDimensions: DEFAULT_DIMENSIONS,
        ImageUsage: [
          generateImage(generateSize(0, 0), [0, 0], generateRecord(100, 3), 'a'),
          generateImage(generateSize(200, 200), [3000, 0], generateRecord(100, 4), 'b'),
        ],
        traces: {},
        devtoolsLogs: {},
        requestInteractive: generateInteractiveFuncError(),
        requestTraceOfTab: generateTraceOfTab(2),
      }, [], context, [], context);
    } catch (err) {
      return;
    }
    assert.ok(false);
  });

  it('finds images loaded before Trace End when interactive throws error (Lantern)', async () => {
    context = {settings: {throttlingMethod: 'simulate'}};
    try {
      await UnusedImages.audit_({
        ViewportDimensions: DEFAULT_DIMENSIONS,
        ImageUsage: [
          generateImage(generateSize(0, 0), [0, 0], generateRecord(100, 1), 'a'),
          generateImage(generateSize(200, 200), [3000, 0], generateRecord(100, 4), 'b'),
        ],
        traces: {},
        devtoolsLogs: {},
        requestInteractive: generateInteractiveFuncError(),
        requestTraceOfTab: generateTraceOfTab(2),
      }, [], context, [], context);
    } catch (err) {
      return;
    }
    assert.ok(false);
  });
});
