"""Incremental rules shared by watch and file-order replay.

Arrival-order exact matches; event-time windows with bounded reordering.
No all-history IP/path counters or unbounded evidence lists.
"""
from collections import Counter, deque
from datetime import timedelta
import heapq

from webloglens.behavior import parse_timestamp
from webloglens.detector import detect_sensitive_paths


class StreamAnalyzer:
    def __init__(self, sensitive_paths=None, window_seconds=60, min_paths=5,
                 lateness_seconds=2, cooldown_seconds=60,
                 max_buffer=512, max_window_records=2048, max_ips=256):
        for name, value, minimum in [('window_seconds', window_seconds, 1),
                                     ('min_paths', min_paths, 2),
                                     ('lateness_seconds', lateness_seconds, 0),
                                     ('cooldown_seconds', cooldown_seconds, 0),
                                     ('max_buffer', max_buffer, 1),
                                     ('max_window_records', max_window_records, 1),
                                     ('max_ips', max_ips, 1)]:
            if type(value) is not int or value < minimum:
                raise ValueError(f'{name} must be an integer >= {minimum}')
        self.max_buffer = max_buffer
        self.max_window_records = max_window_records
        self.max_ips = max_ips
        self.sensitive_paths = sensitive_paths
        self.window_seconds = window_seconds
        self.min_paths = min_paths
        self.lateness_seconds = lateness_seconds
        self.cooldown_seconds = cooldown_seconds
        self.counts = Counter()
        self.status_counts = Counter()
        self.buffer = []
        self.states = {}
        self.sequence = 0
        self.max_time = None
        self.committed = None
        self.last_arrival = None

    def feed(self, record, now):
        self.counts['records'] += 1
        self.status_counts[str(record['fields']['status'])] += 1
        output = [dict(finding, type='finding', evidence=[record])
                  for finding in detect_sensitive_paths([record], self.sensitive_paths)]
        self.counts['path_findings'] += len(output)
        try:
            instant = parse_timestamp(record['fields']['time'])
        except (KeyError, ValueError, OverflowError):
            self.counts['time_errors'] += 1
            return output + [dict(type='time_error', evidence=[record])]
        boundary = self.committed
        if self.max_time is not None:
            watermark = self._before(self.max_time, self.lateness_seconds)
            boundary = watermark if boundary is None else max(boundary, watermark)
        if boundary is not None and instant < boundary:
            self.counts['late_records'] += 1
            return output + [dict(type='late_record', evidence=[record],
                                  boundary_time=boundary.isoformat(),
                                  reason='Excluded from behavior detection; exact rule already evaluated')]
        self.last_arrival = now
        self.sequence += 1
        self.max_time = instant if self.max_time is None else max(self.max_time, instant)
        watermark = self._before(self.max_time, self.lateness_seconds)
        output += self._drain(min(watermark, instant))
        if len(self.buffer) >= self.max_buffer:
            return output + [self._limit('max_buffer', record)]
        heapq.heappush(self.buffer, (instant, self.sequence, record))
        output += self._drain(watermark)
        return output

    @staticmethod
    def _before(instant, seconds):
        try:
            return instant - timedelta(seconds=seconds)
        except OverflowError:
            return instant.replace(year=1, month=1, day=1, hour=0, minute=0, second=0)

    def _limit(self, reason, record):
        self.counts['state_limits'] += 1
        return dict(type='state_limit', reason=reason, evidence=[record],
                    conclusion='Behavior analysis incomplete; exact rule already evaluated')

    def _drain(self, until=None):
        output = []
        while self.buffer and (until is None or self.buffer[0][0] <= until):
            instant, _, record = heapq.heappop(self.buffer)
            self.committed = instant
            cutoff = self._before(instant, self.window_seconds)
            for ip in list(self.states):
                state = self.states[ip]
                while state['window'] and state['window'][0][0] < cutoff:
                    _, path, _ = state['window'].popleft()
                    state['paths'][path] -= 1
                    if not state['paths'][path]:
                        del state['paths'][path]
                if not state['window'] and (state['alert'] is None or
                        (instant - state['alert']).total_seconds() >= self.cooldown_seconds):
                    del self.states[ip]
            fields = record['fields']
            ip = fields['ip']
            if ip not in self.states and len(self.states) >= self.max_ips:
                output.append(self._limit('max_ips', record))
                continue
            if sum(len(s['window']) for s in self.states.values()) >= self.max_window_records:
                output.append(self._limit('max_window_records', record))
                continue
            state = self.states.setdefault(ip, dict(window=deque(), paths=Counter(), alert=None))
            path = fields['target'].split('?', 1)[0]
            state['window'].append((instant, path, record))
            state['paths'][path] += 1
            if len(state['paths']) >= self.min_paths:
                if state['alert'] is not None and (instant - state['alert']).total_seconds() < self.cooldown_seconds:
                    self.counts['suppressed_windows'] += 1
                    continue
                state['alert'] = instant
                self.counts['window_findings'] += 1
                output.append(dict(type='finding', rule_id='multi-path-window-v2', ip=ip,
                    start_time=state['window'][0][0].isoformat(), end_time=instant.isoformat(),
                    window_seconds=self.window_seconds, min_paths=self.min_paths,
                    request_count=len(state['window']), distinct_path_count=len(state['paths']),
                    paths=sorted(state['paths']), evidence=[item[2] for item in state['window']],
                    conclusion='review_required_not_proof_of_attack'))
        return output

    def tick(self, now):
        if self.last_arrival is None:
            return []
        idle = now - self.last_arrival
        output = self._drain() if idle >= self.lateness_seconds else []
        if idle > max(self.window_seconds, self.cooldown_seconds) + self.lateness_seconds:
            self.states.clear()
        return output

    def finish(self):
        return self._drain()

    def snapshot(self):
        return dict(self.counts, status_counts=dict(self.status_counts),
                    buffered_records=len(self.buffer), active_ips=len(self.states),
                    window_records=sum(len(state['window']) for state in self.states.values()))
