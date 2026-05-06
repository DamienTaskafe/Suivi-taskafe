-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Employee Balance Entries
-- ─────────────────────────────────────────────────────────────────────────────
-- Adds a dedicated table for tracking financial operations per employee:
--   advance     = cash advance given to the employee (deducted from amount due)
--   payment     = payment/settlement already made (deducted from amount due)
--   adjustment  = manual correction; direction field controls add/deduct
--
-- Also creates (idempotently) the is_admin_or_manager() SECURITY DEFINER
-- helper function used in RLS policies to avoid recursive profile lookups.
--
-- Idempotent: all DDL uses CREATE OR REPLACE / CREATE TABLE IF NOT EXISTS /
--             DROP POLICY IF EXISTS.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. is_admin_or_manager() — SECURITY DEFINER helper ───────────────────────
-- Uses SECURITY DEFINER so RLS policies on other tables can call it without
-- triggering recursive RLS on public.profiles.

CREATE OR REPLACE FUNCTION public.is_admin_or_manager()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid()
      AND role IN ('admin', 'manager')
  );
$$;

GRANT EXECUTE ON FUNCTION public.is_admin_or_manager() TO authenticated;


-- ── 2. employee_balance_entries table ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.employee_balance_entries (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  employee_id  uuid        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  entry_type   text        NOT NULL
                           CHECK (entry_type IN ('advance', 'payment', 'adjustment')),
  amount       numeric     NOT NULL CHECK (amount >= 0),
  -- direction is only meaningful for entry_type = 'adjustment':
  --   'add'    → adds to amount due (positive correction)
  --   'deduct' → deducts from amount due (negative correction)
  direction    text        NULL
                           CHECK (direction IS NULL OR direction IN ('add', 'deduct')),
  note         text        NULL,
  period_start date        NULL,
  period_end   date        NULL,
  created_by   uuid        NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);


-- ── 3. Row-Level Security ─────────────────────────────────────────────────────

ALTER TABLE public.employee_balance_entries ENABLE ROW LEVEL SECURITY;

-- SELECT: admin/manager sees all; employee sees only their own entries.
DROP POLICY IF EXISTS "balance_entries_select" ON public.employee_balance_entries;
CREATE POLICY "balance_entries_select"
  ON public.employee_balance_entries FOR SELECT
  TO authenticated
  USING (
    employee_id = auth.uid()
    OR public.is_admin_or_manager()
  );

-- INSERT: admin/manager only.
DROP POLICY IF EXISTS "balance_entries_insert" ON public.employee_balance_entries;
CREATE POLICY "balance_entries_insert"
  ON public.employee_balance_entries FOR INSERT
  TO authenticated
  WITH CHECK (public.is_admin_or_manager());

-- UPDATE: admin/manager only.
DROP POLICY IF EXISTS "balance_entries_update" ON public.employee_balance_entries;
CREATE POLICY "balance_entries_update"
  ON public.employee_balance_entries FOR UPDATE
  TO authenticated
  USING (public.is_admin_or_manager())
  WITH CHECK (public.is_admin_or_manager());

-- DELETE: admin/manager only.
DROP POLICY IF EXISTS "balance_entries_delete" ON public.employee_balance_entries;
CREATE POLICY "balance_entries_delete"
  ON public.employee_balance_entries FOR DELETE
  TO authenticated
  USING (public.is_admin_or_manager());


-- ── 4. Refresh PostgREST / Supabase schema cache ──────────────────────────────
NOTIFY pgrst, 'reload schema';
