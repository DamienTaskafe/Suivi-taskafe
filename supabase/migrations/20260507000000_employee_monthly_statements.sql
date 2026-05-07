-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Employee Monthly Statements Archives
-- ─────────────────────────────────────────────────────────────────────────────
-- Adds immutable-style monthly archived bulletins per employee.
-- Idempotent: CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS /
--             DROP POLICY IF EXISTS / CREATE OR REPLACE FUNCTION.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.employee_monthly_statements (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  employee_id       uuid        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  period_start      date        NOT NULL,
  period_end        date        NOT NULL,
  period_label      text        NULL,
  employee_name     text        NULL,
  commission_total  numeric     NOT NULL DEFAULT 0,
  fixed_salary      numeric     NOT NULL DEFAULT 0,
  fuel_amount       numeric     NOT NULL DEFAULT 0,
  advances_total    numeric     NOT NULL DEFAULT 0,
  payments_total    numeric     NOT NULL DEFAULT 0,
  adjustments_total numeric     NOT NULL DEFAULT 0,
  remaining_due     numeric     NOT NULL DEFAULT 0,
  statement_text    text        NULL,
  snapshot          jsonb       NOT NULL DEFAULT '{}'::jsonb,
  status            text        NOT NULL DEFAULT 'archived',
  created_by        uuid        NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS employee_monthly_statements_employee_period_uniq
  ON public.employee_monthly_statements (employee_id, period_start, period_end);

CREATE INDEX IF NOT EXISTS employee_monthly_statements_employee_period_idx
  ON public.employee_monthly_statements (employee_id, period_start DESC);

CREATE OR REPLACE FUNCTION public.tg_set_employee_monthly_statements_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_employee_monthly_statements_updated_at
  ON public.employee_monthly_statements;
CREATE TRIGGER trg_employee_monthly_statements_updated_at
BEFORE UPDATE ON public.employee_monthly_statements
FOR EACH ROW
EXECUTE FUNCTION public.tg_set_employee_monthly_statements_updated_at();

ALTER TABLE public.employee_monthly_statements ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "employee_monthly_statements_select" ON public.employee_monthly_statements;
CREATE POLICY "employee_monthly_statements_select"
  ON public.employee_monthly_statements FOR SELECT
  TO authenticated
  USING (
    employee_id = auth.uid()
    OR public.is_admin_or_manager()
  );

DROP POLICY IF EXISTS "employee_monthly_statements_insert" ON public.employee_monthly_statements;
CREATE POLICY "employee_monthly_statements_insert"
  ON public.employee_monthly_statements FOR INSERT
  TO authenticated
  WITH CHECK (public.is_admin_or_manager());

DROP POLICY IF EXISTS "employee_monthly_statements_update" ON public.employee_monthly_statements;
CREATE POLICY "employee_monthly_statements_update"
  ON public.employee_monthly_statements FOR UPDATE
  TO authenticated
  USING (public.is_admin_or_manager())
  WITH CHECK (public.is_admin_or_manager());

DROP POLICY IF EXISTS "employee_monthly_statements_delete" ON public.employee_monthly_statements;
CREATE POLICY "employee_monthly_statements_delete"
  ON public.employee_monthly_statements FOR DELETE
  TO authenticated
  USING (public.is_admin_or_manager());

NOTIFY pgrst, 'reload schema';
