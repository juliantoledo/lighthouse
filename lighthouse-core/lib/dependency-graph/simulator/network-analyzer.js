/**
 * @license Copyright 2018 Google Inc. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
'use strict';

const URL = require('../../url-shim');
const INITIAL_CWD = 14 * 1024;

module.exports = class NetworkAnalyzer {
  static groupByOrigin(records) {
    const grouped = new Map();
    records.forEach(item => {
      const key = new URL(item.url).origin;
      const group = grouped.get(key) || [];
      group.push(item);
      grouped.set(key, group);
    });
    return grouped;
  }

  static summary(values) {
    if (values instanceof Map) {
      const summaryByKey = new Map();
      const allEstimates = [];
      for (const [key, estimates] of values) {
        summaryByKey.set(key, NetworkAnalyzer.summary(estimates));
        allEstimates.push(...estimates);
      }

      summaryByKey.set(NetworkAnalyzer.SUMMARY, NetworkAnalyzer.summary(allEstimates));
      return summaryByKey;
    }

    values.sort((a, b) => a - b);

    return {
      min: values[0],
      max: values[values.length - 1],
      avg: values.reduce((a, b) => a + b, 0) / values.length,
      median: values[Math.floor((values.length - 1) / 2)],
    };
  }

  static _estimateValueByOrigin(records, iteratee) {
    const connectionWasReused = NetworkAnalyzer.estimateIfConnectionWasReused(records);
    const groupedByOrigin = NetworkAnalyzer.groupByOrigin(records);

    const estimates = new Map();
    for (const [origin, originRecords] of groupedByOrigin.entries()) {
      let originEstimates = [];

      for (const record of originRecords) {
        const timing = record._timing;
        if (!timing) continue;

        const value = iteratee({
          record,
          timing,
          connectionReused: connectionWasReused.get(record.requestId),
        });
        if (typeof value !== 'undefined') {
          originEstimates = originEstimates.concat(value);
        }
      }

      if (!originEstimates.length) continue;
      estimates.set(origin, originEstimates);
    }

    return estimates;
  }

  static _estimateRTTByOriginViaTCPTiming(records) {
    return NetworkAnalyzer._estimateValueByOrigin(records, ({record, timing, connectionReused}) => {
      if (connectionReused) return;

      if (timing.sslStart > 0 && timing.sslEnd > 0) {
        return [timing.connectEnd - timing.sslStart, timing.sslStart - timing.connectStart];
      } else if (timing.connectStart > 0 && timing.connectEnd > 0) {
        return timing.connectEnd - timing.connectStart;
      }
    });
  }

  static _estimateRTTByOriginViaDownloadTiming(records, options) {
    return NetworkAnalyzer._estimateValueByOrigin(records, ({record, timing, connectionReused}) => {
      if (connectionReused) return;
      if (record.transferSize <= INITIAL_CWD) return;
      if (!Number.isFinite(timing.receiveHeadersEnd) || timing.receiveHeadersEnd < 0) return;

      const totalTime = (record.endTime - record.startTime) * 1000;
      const downloadTimeAfterFirstByte = totalTime - timing.receiveHeadersEnd;
      const numberOfRoundTrips = Math.log2(record.transferSize / INITIAL_CWD);
      return downloadTimeAfterFirstByte / numberOfRoundTrips;
    });
  }

  static _estimateRTTByOriginViaSendStartTiming(records) {
    return NetworkAnalyzer._estimateValueByOrigin(records, ({record, timing, connectionReused}) => {
      if (connectionReused) return;
      if (!Number.isFinite(timing.sendStart) || timing.sendStart < 0) return;

      let roundTrips = 1;
      if (record.parsedURL.scheme === 'https') roundTrips += 1;
      return timing.sendStart / roundTrips;
    });
  }

  static _estimateResponseTimeByOrigin(records, rttByOrigin) {
    return NetworkAnalyzer._estimateValueByOrigin(records, ({record, timing}) => {
      if (!Number.isFinite(timing.receiveHeadersEnd) || timing.receiveHeadersEnd < 0) return;
      if (!Number.isFinite(timing.sendEnd) || timing.sendEnd < 0) return;

      const ttfb = timing.receiveHeadersEnd - timing.sendEnd;
      const origin = new URL(record.url).origin;
      const rtt = rttByOrigin.get(origin) || rttByOrigin.get(NetworkAnalyzer.SUMMARY);
      return Math.max(ttfb - rtt, 0);
    });
  }

  /**
   * Returns a map of requestId -> connectionReused, estimating the information if the information
   * available in the records themselves appears untrustworthy.
   *
   * @param {!WebInspector.NetworkRequest} records
   * @return {!Map<string, boolean>}
   */
  static estimateIfConnectionWasReused(records) {
    const connectionIds = new Set(records.map(record => record.connectionId));
    // If the records actually have distinct connectionIds we can reuse these.
    if (connectionIds.size > 1 || records.size < 2) {
      return new Map(records.map(record => [record.requestId, record.connectionReused]));
    }

    // Otherwise we're on our own, arecord may not have needed a fresh connection if...
    //   - It was not the first request to the domain
    //   - It was H2
    //   - It was after the first request to the domain ended
    const connectionWasReused = new Map();
    const groupedByOrigin = NetworkAnalyzer.groupByOrigin(records);
    for (const [origin, originRecords] of groupedByOrigin.entries()) {
      const earliestReusePossible = originRecords
        .map(record => record.endTime)
        .reduce((a, b) => Math.min(a, b), Infinity);

      for (const record of originRecords) {
        connectionWasReused.set(
          record.requestId,
          record.startTime >= earliestReusePossible || record.protocol === 'h2'
        );
      }

      const firstRecord = originRecords.reduce((a, b) => (a.startTime > b.startTime ? b : a), {
        startTime: Infinity,
      });
      connectionWasReused.set(firstRecord.requestId, false);
    }

    return connectionWasReused;
  }

  static estimateRTTByOrigin(records, options) {
    options = Object.assign(
      {
        // TCP connection handshake information will be used when available, but for testing
        // it's useful to see how the coarse estimates compare with higher fidelity data
        forceCoarseEstimates: false,
        // coarse estimates include lots of extra time and noise
        // multiply by some factor to deflate the RTT estimates a bit
        coarseEstimateMultiplier: 0.5,
      },
      options
    );

    let estimatesByOrigin = NetworkAnalyzer._estimateRTTByOriginViaTCPTiming(records);
    if (!estimatesByOrigin.size || options.forceCoarseEstimates) {
      estimatesByOrigin = new Map();
      const estimatesViaDownload = NetworkAnalyzer._estimateRTTByOriginViaDownloadTiming(records);
      const estimatesViaSendStart = NetworkAnalyzer._estimateRTTByOriginViaSendStartTiming(
        records,
        options.estimateResponseTime
      );

      for (const [origin, estimates] of estimatesViaDownload.entries()) {
        estimatesByOrigin.set(origin, estimates);
      }

      for (const [origin, estimates] of estimatesViaSendStart.entries()) {
        const existing = estimatesByOrigin.get(origin) || [];
        estimatesByOrigin.set(origin, existing.concat(estimates));
      }

      for (const estimates of estimatesByOrigin.values()) {
        estimates.forEach((x, i) => (estimates[i] = x * options.coarseEstimateMultiplier));
      }
    }

    if (!estimatesByOrigin.size) throw new Error('No timing information available');
    return NetworkAnalyzer.summary(estimatesByOrigin);
  }

  static estimateServerResponseTimeByOrigin(records, options) {
    options = Object.assign(
      {
        rttByOrigin: null,
      },
      options
    );

    let rttByOrigin = options.rttByOrigin;
    if (!rttByOrigin) {
      rttByOrigin = NetworkAnalyzer.estimateRTTByOrigin(records, options);
      for (const [origin, summary] of rttByOrigin.entries()) {
        rttByOrigin.set(origin, summary.min);
      }
    }

    const estimatesByOrigin = NetworkAnalyzer._estimateResponseTimeByOrigin(records, rttByOrigin);
    return NetworkAnalyzer.summary(estimatesByOrigin);
  }
};

module.exports.SUMMARY = Symbol('__SUMMARY__');
