ALTER TABLE authorization_codes
  ADD COLUMN family_id UUID NOT NULL DEFAULT gen_random_uuid();
