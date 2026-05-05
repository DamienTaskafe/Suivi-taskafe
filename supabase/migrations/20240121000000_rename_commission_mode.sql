-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Rename remuneration mode 'commission_only' → 'commission_simple'
-- ─────────────────────────────────────────────────────────────────────────────
-- Idempotent: safe to run multiple times.
-- Renames the legacy value 'commission_only' to 'commission_simple' and
-- updates the CHECK constraint accordingly.
-- Also ensures the SQL schema introduced in 20240115 is aligned with the
-- updated field names requested in the issue:
--   remuneration_mode  → default 'commission_simple'
--   fixed_salary alias → fixed_monthly_salary (already correct)
-- ─────────────────────────────────────────────────────────────────────────────

-- Step 1: migrate existing rows that still use the old value
UPDATE public.profiles
  SET remuneration_mode = 'commission_simple'
  WHERE remuneration_mode = 'commission_only';

-- Step 2: drop the old CHECK constraint (may or may not be named)
ALTER TABLE public.profiles
  DROP CONSTRAINT IF EXISTS profiles_remuneration_mode_check;

-- The ADD COLUMN IF NOT EXISTS inline CHECK in migration 20240115 was added
-- as an unnamed constraint on the column.  PostgreSQL names it automatically
-- as profiles_remuneration_mode_check1 or similar.  Drop all variants.
DO $$
DECLARE
  con_name text;
BEGIN
  FOR con_name IN
    SELECT conname
    FROM pg_constraint
    WHERE conrelid = 'public.profiles'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%remuneration_mode%'
  LOOP
    EXECUTE format('ALTER TABLE public.profiles DROP CONSTRAINT IF EXISTS %I', con_name);
  END LOOP;
END;
$$;

-- Step 3: add the updated CHECK constraint with the new value name
ALTER TABLE public.profiles
  ADD CONSTRAINT profiles_remuneration_mode_check
  CHECK (remuneration_mode IN ('commission_simple', 'fixed_plus_commission'));

-- Step 4: update the column default so new rows default to 'commission_simple'
ALTER TABLE public.profiles
  ALTER COLUMN remuneration_mode SET DEFAULT 'commission_simple';
