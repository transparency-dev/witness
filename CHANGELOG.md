# transparency-dev/witness Changelog

## HEAD

* Witness binary emits only `cosignature/v1` signature.
* Added `witness.ErrBadRequest`, which `witness.ErrOldSizeInvalid`, `witness.ErrInvalidCheckpoint` and
  `witness.ErrSubtreeRangeInvalid` now wrap. `client/http` returns it for `400` responses, whose cause
  the tlog-witness protocol does not convey, and detects an invalid old size locally before sending.

