-- Down: no-op. Force-expiry in up is one-way — plaintext tokens are gone,
-- so "un-expiring" would leave rows whose token_hash format the store no
-- longer understands. Users re-request a reset instead.
SELECT 1;
