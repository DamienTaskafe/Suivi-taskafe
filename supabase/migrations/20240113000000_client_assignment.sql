-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Client assignment foundation
-- ─────────────────────────────────────────────────────────────────────────────
-- Business context
-- ─────────────────
-- Sales reps prospect and manage their own clients, but clients remain the
-- property of the business.  When an employee leaves, the admin must be able
-- to keep those clients and reassign them or leave them unassigned.
--
-- What this migration adds
-- ─────────────────────────
-- 1. Four nullable / default-safe columns on public.clients:
--    • assigned_user_id — FK to auth.users; the employee currently managing
--                         this client (NULL = unassigned / legacy).
--    • assigned_at      — timestamp when the current assignment was made.
--    • assigned_by      — FK to auth.users; who last assigned or reassigned.
--    • client_status    — lifecycle stage: prospect | active | inactive | lost.
--                         Defaults to 'active' so existing rows are unchanged.
--
-- 2. A new table public.client_assignment_history that records every
--    reassignment event:
--    • client_id        — FK to clients (CASCADE DELETE so history is cleaned up).
--    • previous_user_id — the employee who previously held the client (nullable).
--    • new_user_id      — the employee who receives the client (nullable).
--    • changed_by       — admin / manager who performed the reassignment.
--    • changed_at       — timestamp (server default).
--    • note             — optional free-text comment.
--
-- 3. RLS policies on client_assignment_history:
--    • Admins and managers can SELECT the full history.
--    • Any authenticated user can INSERT (app inserts on the user's behalf).
--
-- Compatibility guarantees
-- ─────────────────────────
-- • All new columns use IF NOT EXISTS / DEFAULT-safe patterns: existing rows
--   are not broken — they simply have NULL assignment and status = 'active'.
-- • The clients RLS policies are NOT changed here: SELECT remains open to all
--   authenticated users.  Employee-scoped filtering is applied at the
--   application layer (index.html loadCloudData) using the assigned_user_id
--   column so unassigned legacy clients continue to work for everyone.
-- • No existing triggers, functions, or indexes are modified.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. Extend public.clients ─────────────────────────────────────────────────

ALTER TABLE public.clients
  ADD COLUMN IF NOT EXISTS assigned_user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS assigned_at       timestamptz,
  ADD COLUMN IF NOT EXISTS assigned_by       uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS client_status     text NOT NULL DEFAULT 'active';


-- ── 2. Create public.client_assignment_history ───────────────────────────────

CREATE TABLE IF NOT EXISTS public.client_assignment_history (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id        uuid        NOT NULL REFERENCES public.clients(id) ON DELETE CASCADE,
  previous_user_id uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  new_user_id      uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  changed_by       uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  changed_at       timestamptz NOT NULL DEFAULT now(),
  note             text
);


-- ── 3. RLS on client_assignment_history ──────────────────────────────────────

ALTER TABLE public.client_assignment_history ENABLE ROW LEVEL SECURITY;

-- Admins and managers can read the full reassignment history.
DROP POLICY IF EXISTS "client_history_select_manager_admin" ON public.client_assignment_history;
CREATE POLICY "client_history_select_manager_admin"
  ON public.client_assignment_history FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('manager', 'admin')
    )
  );

-- Any authenticated user can insert a history row (the app inserts on behalf
-- of the acting user when a reassignment is performed).
DROP POLICY IF EXISTS "client_history_insert_auth" ON public.client_assignment_history;
CREATE POLICY "client_history_insert_auth"
  ON public.client_assignment_history FOR INSERT
  TO authenticated
  WITH CHECK (true);
