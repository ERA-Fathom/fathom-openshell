# Changelog

## 0.2.1 (2026-10-01)

- The loader no longer breaks on a response whose body is a JSON list (a GitHub directory listing); the scan for messages
  that carry tool calls reads model traffic only.
- Claims: placeholder values ("none", "not reported", "n/a", "(not provided)", a lone dash) assert nothing, in claims as in
  writes. A failure line in a final message laid out per write (path, status, facts) governs only that write's block; a
  key-only header above a path line belongs to its block; "Path:" labels and "HTTP status: 4xx" lines in markdown count.
- The joined read sends each tool call's arguments, so the hosted read (0.6.1) aligns concurrent calls to the deliveries
  for the path each one names.

## 0.2.0 (2026-09-30)

- `--join`: the joined read against the hosted read 0.6.0 (the delivery record lined up with the model traffic).

## 0.1.0 (2026-09-30)

- The capture middleware, the WatchSandbox recorder, the adapters, and the read.
