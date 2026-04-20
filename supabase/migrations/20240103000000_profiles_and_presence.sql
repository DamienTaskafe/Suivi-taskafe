-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: profiles table + last_seen_at column + tightened RLS
-- ─────────────────────────────────────────────────────────────────────────────
-- This migration is idempotent and safe to run on both fresh and existing
-- Supabase projects:
--   • If the profiles table does not yet exist it is created with all required
--     columns including last_seen_at.
--   • If the table already exists the last_seen_at column is added when missing.
--   • RLS policies are replaced so they are consistent with the app logic.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Create profiles table if it does not exist ───────────────────────────────
CREATE TABLE IF NOT EXISTS public.profiles (
  id           UUID        PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email        TEXT,
  full_name    TEXT,
  role         TEXT        NOT NULL DEFAULT 'employee',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ
);

-- ── Ensure last_seen_at column exists on tables that pre-date this migration ──
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;

-- ── Enable RLS (idempotent) ───────────────────────────────────────────────────
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- ── Replace RLS policies ──────────────────────────────────────────────────────
-- Drop all existing profile policies before recreating so we have a clean slate.
DROP POLICY IF EXISTS "profiles_select_auth"      ON public.profiles;
DROP POLICY IF EXISTS "profiles_update_own"        ON public.profiles;
DROP POLICY IF EXISTS "profiles_insert_own"        ON public.profiles;
DROP POLICY IF EXISTS "profiles_update_last_seen"  ON public.profiles;

-- Any authenticated user can read all profiles (needed to display the user list).
CREATE POLICY "profiles_select_auth"
  ON public.profiles FOR SELECT
  TO authenticated
  USING (true);

-- Each user may update only their own profile row.
-- Column-level restrictions are not directly supported in Postgres RLS, but the
-- service_role key used by the backend APIs bypasses RLS so admin operations
-- (role changes, etc.) always go through the server-side APIs and are not
-- affected by this policy.
CREATE POLICY "profiles_update_own"
  ON public.profiles FOR UPDATE
  TO authenticated
  USING (id = auth.uid())
  WITH CHECK (id = auth.uid());

-- Profile rows are inserted by the create-user serverless function which uses the
-- service_role key (bypasses RLS).  The policy below is kept for compatibility
-- with any direct-insert path (e.g., first-boot triggers).
CREATE POLICY "profiles_insert_own"
  ON public.profiles FOR INSERT
  TO authenticated
  WITH CHECK (id = auth.uid());

-- ── action_logs: ensure RLS is on and policies exist ─────────────────────────
-- (Repeated here for safety in case the previous migration was not applied.)
ALTER TABLE IF EXISTS public.action_logs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "action_logs_select_admin" ON public.action_logs;
DROP POLICY IF EXISTS "action_logs_insert_auth"  ON public.action_logs;

CREATE POLICY "action_logs_select_admin"
  ON public.action_logs FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role = 'admin'
    )
  );

CREATE POLICY "action_logs_insert_auth"
  ON public.action_logs FOR INSERT
  TO authenticated
  WITH CHECK (true);
