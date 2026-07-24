package postgres

import (
	"context"
	"fmt"
)

// SQL helper functions for the inline-v2 model: they read the key version (KID)
// straight from a stored ciphertext, with no companion column. Install them once
// per database (InstallFunctions); then:
//
//   - metrics per key on a scalar bytea column:
//       SELECT cryptostore_kid(col) AS kid, count(*) FROM t GROUP BY 1;
//     (back it with a functional index: CREATE INDEX ON t (cryptostore_kid(col)))
//   - metrics per key over encrypted attributes inside a jsonb document:
//       SELECT k, count(*) FROM t CROSS JOIN LATERAL cryptostore_kids(t.doc) k GROUP BY 1;
//   - migration predicate for a single json attribute (path-aware, so it also
//     catches a plaintext attribute that was never encrypted):
//       WHERE cryptostore_pending(doc #> '{ssn}', $primary)
//     cryptostore_pending mirrors the codec's skip rules — false for absent, json
//     null, empty string, or already-primary ciphertext; true for plaintext or a
//     non-primary ciphertext at that path.
//
// cryptostore_kid returns NULL for a value that is not our ciphertext, so it also
// serves as an "is this encrypted?" predicate. The functions decode the protobuf
// varint KID without authenticating — a corrupt header yields a meaningless kid;
// trust it only for routing/metrics, not as a security boundary.
//
// The framing they expect matches cryptostore.FrameBinary / FrameText:
//   - bytea:        \x00 \x01  ‖ cryptobox-blob   (NUL, format version)
//   - json string:  "cbox:" ‖ base64(cryptobox-blob)

// installSQL renders the CREATE FUNCTION statements into the given schema.
func installSQL(schema string) string {
	return fmt.Sprintf(`
CREATE OR REPLACE FUNCTION %[1]s.cryptostore_kid_raw(v bytea) RETURNS integer
  LANGUAGE sql IMMUTABLE PARALLEL SAFE RETURNS NULL ON NULL INPUT AS $$
  SELECT CASE
    WHEN length(v) = 0 THEN NULL
    WHEN (get_byte(v,0) & 128) = 0 THEN  get_byte(v,0) & 127
    WHEN length(v) >= 2 AND (get_byte(v,1) & 128) = 0
      THEN (get_byte(v,0) & 127) | ((get_byte(v,1) & 127) << 7)
    WHEN length(v) >= 3 AND (get_byte(v,2) & 128) = 0
      THEN (get_byte(v,0) & 127) | ((get_byte(v,1) & 127) << 7) | ((get_byte(v,2) & 127) << 14)
    ELSE NULL
  END
$$;

CREATE OR REPLACE FUNCTION %[1]s.cryptostore_kid(v bytea) RETURNS integer
  LANGUAGE sql IMMUTABLE PARALLEL SAFE RETURNS NULL ON NULL INPUT AS $$
  SELECT CASE
    WHEN length(v) >= 3 AND substring(v for 2) = '\x0001'::bytea
      THEN %[1]s.cryptostore_kid_raw(substring(v from 3))
    ELSE NULL
  END
$$;

CREATE OR REPLACE FUNCTION %[1]s.cryptostore_kids(doc jsonb) RETURNS SETOF integer
  LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $body$
DECLARE
  elem jsonb;
  s    text;
BEGIN
  IF doc IS NULL THEN
    RETURN;
  END IF;
  CASE jsonb_typeof(doc)
    WHEN 'object' THEN
      FOR elem IN SELECT value FROM jsonb_each(doc) LOOP
        RETURN QUERY SELECT * FROM %[1]s.cryptostore_kids(elem);
      END LOOP;
    WHEN 'array' THEN
      FOR elem IN SELECT value FROM jsonb_array_elements(doc) LOOP
        RETURN QUERY SELECT * FROM %[1]s.cryptostore_kids(elem);
      END LOOP;
    WHEN 'string' THEN
      s := doc #>> '{}';
      IF left(s, 5) = 'cbox:' THEN
        RETURN NEXT %[1]s.cryptostore_kid_raw(decode(substr(s, 6), 'base64'));
      END IF;
    ELSE
    -- number / boolean / null: nothing to extract
  END CASE;
END
$body$;

CREATE OR REPLACE FUNCTION %[1]s.cryptostore_pending(v jsonb, primary_kid integer) RETURNS boolean
  LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE
    WHEN v IS NULL OR jsonb_typeof(v) = 'null' THEN false   -- absent / json null: skipped by the codec
    WHEN jsonb_typeof(v) = 'string' THEN
      CASE
        WHEN v #>> '{}' = '' THEN false                     -- empty string: skipped by the codec
        WHEN left(v #>> '{}', 5) = 'cbox:'                  -- already encrypted: pending iff not primary
          THEN %[1]s.cryptostore_kid_raw(decode(substr(v #>> '{}', 6), 'base64')) IS DISTINCT FROM primary_kid
        ELSE true                                           -- plaintext string → encrypt
      END
    ELSE true                                               -- plaintext number/object/array/bool → encrypt
  END
$$;
`, schema)
}

// InstallFunctions creates (or replaces) the cryptostore SQL helper functions in
// schema (empty → "public"). It is idempotent.
func InstallFunctions(ctx context.Context, db DB, schema string) error {
	if schema == "" {
		schema = defaultSchema
	}
	if _, err := db.Exec(ctx, installSQL(schema)); err != nil {
		return fmt.Errorf("postgres: install functions: %w", err)
	}
	return nil
}
