-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Commission and Remuneration System
-- ─────────────────────────────────────────────────────────────────────────────
-- This is a non-destructive, backward-compatible migration.
--
-- It adds:
--   1. Remuneration fields on public.profiles:
--        remuneration_mode    — 'commission_only' | 'fixed_plus_commission'
--        commission_rates     — JSONB map of gamme → DHS per unit (kg or paquet)
--                               e.g. {"ORO":5.0,"RIO":6.0,"ESPRESSO":7.0,...}
--        fixed_monthly_salary — monthly fixed component (only used in mixed mode)
--        fuel_allowance       — monthly fuel reimbursement (any mode)
--
--   2. public.remuneration_history — periodic snapshots of computed remunerations
--        Allows admins to record a "calculated and validated" snapshot for any
--        period so that past results remain auditable even if rates change later.
--
--   3. RLS policies for remuneration_history and an admin-level profiles UPDATE
--        policy so admins can configure remuneration settings for any employee.
--
-- Idempotent: all DDL uses IF NOT EXISTS / IF EXISTS / ADD COLUMN IF NOT EXISTS.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. Add remuneration columns to profiles ───────────────────────────────────

ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS remuneration_mode
    TEXT NOT NULL DEFAULT 'commission_only'
    CHECK (remuneration_mode IN ('commission_only', 'fixed_plus_commission'));

ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS commission_rates JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS fixed_monthly_salary
    NUMERIC NOT NULL DEFAULT 0 CHECK (fixed_monthly_salary >= 0);

ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS fuel_allowance
    NUMERIC NOT NULL DEFAULT 0 CHECK (fuel_allowance >= 0);


-- ── 2. remuneration_history table ─────────────────────────────────────────────
-- Stores periodic commission snapshots that have been explicitly validated/saved
-- by an admin.  Changing future commission rates never alters past snapshots.

CREATE TABLE IF NOT EXISTS public.remuneration_history (
  id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              uuid        NOT NULL
                                   REFERENCES public.profiles(id) ON DELETE CASCADE,
  period_start         date        NOT NULL,
  period_end           date        NOT NULL,
  -- Breakdown of total quantities per category sold during the period
  total_kg_by_category jsonb       NOT NULL DEFAULT '{}'::jsonb,
  total_commission     numeric     NOT NULL DEFAULT 0 CHECK (total_commission >= 0),
  total_fixed          numeric     NOT NULL DEFAULT 0 CHECK (total_fixed >= 0),
  fuel_reimbursement   numeric     NOT NULL DEFAULT 0 CHECK (fuel_reimbursement >= 0),
  notes                text,
  calculated_by        uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at           timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.remuneration_history ENABLE ROW LEVEL SECURITY;


-- ── 3. RLS policies for remuneration_history ──────────────────────────────────

-- Employees see only their own history; admins/managers see all.
DROP POLICY IF EXISTS "remuneration_history_select" ON public.remuneration_history;
CREATE POLICY "remuneration_history_select"
  ON public.remuneration_history FOR SELECT
  TO authenticated
  USING (
    user_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

-- Only admins/managers may insert snapshots.
DROP POLICY IF EXISTS "remuneration_history_insert" ON public.remuneration_history;
CREATE POLICY "remuneration_history_insert"
  ON public.remuneration_history FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

-- Only admins may delete snapshots.
DROP POLICY IF EXISTS "remuneration_history_delete" ON public.remuneration_history;
CREATE POLICY "remuneration_history_delete"
  ON public.remuneration_history FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role = 'admin'
    )
  );


-- ── 4. Allow admins to update any profile row ─────────────────────────────────
-- The existing profiles_update_own policy lets each user update only their own
-- row.  This additional policy lets admins configure remuneration settings on
-- any employee's profile without requiring the service-role key in the frontend.
--
-- PostgreSQL RLS uses OR semantics across multiple UPDATE policies, so an admin
-- will pass this policy (even for rows that are not their own) while a regular
-- employee will still be governed solely by profiles_update_own.

DROP POLICY IF EXISTS "profiles_update_admin" ON public.profiles;
CREATE POLICY "profiles_update_admin"
  ON public.profiles FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles AS p
      WHERE p.id = auth.uid() AND p.role = 'admin'
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.profiles AS p
      WHERE p.id = auth.uid() AND p.role = 'admin'
    )
  );
