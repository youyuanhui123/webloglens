"""Bounded site partitions; each reuses the existing incremental rule core.

Per-site resource limits multiply by max_sites. Admission is first-seen for this
run (no silent eviction/reset of watermarks or cooldown). Combined input keeps
using StreamAnalyzer directly.
"""
from collections import Counter

from webloglens.detector import detect_sensitive_paths
from webloglens.stream import StreamAnalyzer


class SiteAnalyzer:
    def __init__(self, max_sites=16, **options):
        if type(max_sites) is not int or not 1 <= max_sites <= 128:
            raise ValueError('max_sites must be an integer in 1..128')
        probe = StreamAnalyzer(**options)  # Validate before outputs, including empty input.
        self.max_sites = max_sites
        self.options = options
        self.sites = {}
        self.excluded = Counter()
        self.excluded_statuses = Counter()
        self.upper_bounds = dict(buffered_records=probe.max_buffer * max_sites,
                                 window_records=probe.max_window_records * max_sites,
                                 active_site_ip_pairs=probe.max_ips * max_sites)

    @staticmethod
    def _tag(site, events):
        return [dict(event, site=site) for event in events]

    def feed(self, record, now):
        site = record['fields'].get('site')
        if (not isinstance(site, str) or not site or len(site) > 255 or
                any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in site)):
            raise ValueError('A validated, nonempty configured site identifier is required')
        site.encode('utf-8')
        if site not in self.sites:
            if len(self.sites) >= self.max_sites:
                # Never retain unknown-site maps, IPs or watermarks. Still account
                # for every request and evaluate the stateless exact rule.
                self.excluded['records'] += 1
                self.excluded_statuses[str(record['fields']['status'])] += 1
                exact = [dict(finding, type='finding', evidence=[record])
                         for finding in detect_sensitive_paths([record], self.options.get('sensitive_paths'))]
                self.excluded['path_findings'] += len(exact)
                self.excluded['state_limits'] += 1
                self.excluded['site_limit_records'] += 1
                return self._tag(site, exact + [dict(type='state_limit', reason='max_sites',
                    evidence=[record], conclusion='Site not admitted; behavior excluded; exact rule evaluated')])
            self.sites[site] = StreamAnalyzer(**self.options)
        return self._tag(site, self.sites[site].feed(record, now))

    def tick(self, now):
        return [event for site, core in self.sites.items() for event in self._tag(site, core.tick(now))]

    def finish(self):
        return [event for site, core in self.sites.items() for event in self._tag(site, core.finish())]

    def snapshot(self):
        totals, statuses = Counter(self.excluded), Counter(self.excluded_statuses)
        per_site = {}
        for site, core in self.sites.items():
            summary = core.snapshot()
            per_site[site] = summary
            statuses.update(summary['status_counts'])
            totals.update({key: value for key, value in summary.items() if key != 'status_counts'})
        for name in ('records', 'buffered_records', 'active_ips', 'window_records'):
            totals.setdefault(name, 0)
        return dict(totals, status_counts=dict(statuses), allocated_sites=len(self.sites),
                    max_sites=self.max_sites, sites=per_site,
                    capacity_scope='per-site limits; first admitted sites retained for run',
                    aggregate_upper_bounds=dict(self.upper_bounds))
