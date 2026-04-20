-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: action_logs table + RLS policies
-- Table: action_logs
--
-- Stores audit events for key admin actions:
--   - user login
--   - collaborator creation
--   - collaborator deletion
--   - role/status change
--
-- Only admins can read logs; any authenticated user can insert.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Create action_logs table (idempotent) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.action_logs (
  id          UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  action_type TEXT        NOT NULL,
  user_id     UUID        REFERENCES auth.users(id) ON DELETE SET NULL,
  user_email  TEXT,
  details     JSONB,
  created_at  TIMESTAMPTZ DEFAULT now() NOT NULL
);

-- ── Enable RLS ────────────────────────────────────────────────────────────────
ALTER TABLE IF EXISTS public.action_logs ENABLE ROW LEVEL SECURITY;

-- ── Policies ──────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "action_logs_select_admin" ON public.action_logs;
DROP POLICY IF EXISTS "action_logs_insert_auth"  ON public.action_logs;

-- Only admins can read the action log
CREATE POLICY "action_logs_select_admin"
  ON public.action_logs FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role = 'admin'
    )
  );

-- Any authenticated user can insert log entries (writes happen client-side on
-- behalf of the current user; the user_id column ties the row back to them)
CREATE POLICY "action_logs_insert_auth"
  ON public.action_logs FOR INSERT
  TO authenticated
  WITH CHECK (true);
