-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Add preferred_language to profiles
-- ─────────────────────────────────────────────────────────────────────────────
-- Idempotent: safe to run multiple times.
-- Adds a preferred_language column so each user's language choice is persisted
-- in Supabase.  Accepted values: 'fr', 'ar', 'darija'.  Defaults to 'fr'.
-- ─────────────────────────────────────────────────────────────────────────────

-- Step 1: add column if it doesn't exist (nullable first to handle existing rows)
ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS preferred_language text;

-- Step 2: back-fill any existing NULL rows so the NOT NULL constraint below
-- can be applied safely even on a database that already has profile rows.
UPDATE public.profiles
  SET preferred_language = 'fr'
  WHERE preferred_language IS NULL;

-- Step 3: set NOT NULL and default
ALTER TABLE public.profiles
  ALTER COLUMN preferred_language SET NOT NULL,
  ALTER COLUMN preferred_language SET DEFAULT 'fr';

-- Step 4: drop any pre-existing version of the CHECK constraint (idempotent)
ALTER TABLE public.profiles
  DROP CONSTRAINT IF EXISTS profiles_preferred_language_check;

-- Step 5: add the CHECK constraint
ALTER TABLE public.profiles
  ADD CONSTRAINT profiles_preferred_language_check
  CHECK (preferred_language IN ('fr', 'ar', 'darija'));
