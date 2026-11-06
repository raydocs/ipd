# Read-only terminal /cc (draft)
Success criterion: a trusted-origin-bound POSIX sh script uses only installed curl,
contacts only a dedicated non-persisting caller-IP endpoint, rejects untrusted
responses, and passes loopback integration tests without reading or uploading
private local signals. No browser, runner, score or default behavior changes.
