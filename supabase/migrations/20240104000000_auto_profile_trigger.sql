-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: auto-create profile rows for Supabase Auth users
-- ─────────────────────────────────────────────────────────────────────────────
-- Problem: when an admin account is created directly in the Supabase dashboard
-- (or via the Supabase Auth API outside of the /api/create-user flow), no row
-- is inserted into public.profiles.  The /api/create-user backend cannot verify
-- the caller's admin role because the profile row simply does not exist.
--
-- Fix:
--   1. An AFTER INSERT trigger on auth.users automatically creates a
--      corresponding profiles row with the role stored in raw_app_meta_data
--      (falls back to 'employee' when the field is absent).
--   2. A one-time backfill inserts profiles rows for any existing auth.users
--      that are already missing one, using the same role logic.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Trigger function ──────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.handle_new_auth_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  _role TEXT;
BEGIN
  -- Prefer the role already stored in raw_app_meta_data; default to 'employee'.
  _role := COALESCE(
    LOWER(TRIM((NEW.raw_app_meta_data->>'role')::TEXT)),
    'employee'
  );
  -- Only accept known roles; anything unknown becomes 'employee'.
  IF _role NOT IN ('admin', 'manager', 'employee') THEN
    _role := 'employee';
  END IF;

  INSERT INTO public.profiles (id, email, full_name, role, created_at)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'full_name', ''),
    _role,
    now()
  )
  ON CONFLICT (id) DO NOTHING;  -- safe to re-run; never overwrites an existing profile

  RETURN NEW;
END;
$$;

-- ── Attach trigger to auth.users ──────────────────────────────────────────────
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_auth_user();

-- ── Backfill: create profiles for existing auth users that have none ──────────
-- Uses raw_app_meta_data->>'role' when available; defaults to 'employee'.
-- Existing profiles are never touched (ON CONFLICT DO NOTHING).
INSERT INTO public.profiles (id, email, full_name, role, created_at)
SELECT
  u.id,
  u.email,
  COALESCE(u.raw_user_meta_data->>'full_name', ''),
  CASE
    WHEN LOWER(TRIM(u.raw_app_meta_data->>'role')) IN ('admin', 'manager', 'employee')
    THEN LOWER(TRIM(u.raw_app_meta_data->>'role'))
    ELSE 'employee'
  END,
  now()
FROM auth.users u
LEFT JOIN public.profiles p ON p.id = u.id
WHERE p.id IS NULL;
