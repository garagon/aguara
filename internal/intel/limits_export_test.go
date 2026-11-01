package intel

import "context"

// These entry points exist only in the test binary. Production callers cannot
// choose different limits, and tests never mutate package-wide state.
func LoadWithLimitForTest(s *Store, limit int64) (*Snapshot, error) {
	return s.load(limit)
}

func UpdateWithLimitForTest(ctx context.Context, opts UpdateOptions, limit int64) (*UpdateResult, error) {
	return update(ctx, opts, limit)
}
