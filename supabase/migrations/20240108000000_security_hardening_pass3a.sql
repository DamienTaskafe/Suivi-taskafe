-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Security hardening pass 3A — quick wins
-- ─────────────────────────────────────────────────────────────────────────────
-- Scope: targeted low-risk hardening following passes 1 and 2.  Three concerns
-- addressed here; each is independent and safe to roll back individually.
--
-- What this migration does
-- ─────────────────────────
-- 1. Guard sales.paid against direct-API modification by employees
--    The UI already restricts toggling paid to roles with tasks.toggle_paid =
--    true (manager / admin by default), but that guard lives only at the
--    application layer.  An employee JWT holder could bypass the frontend and
--    set paid = true or paid = false directly via the Supabase REST API.
--    A BEFORE UPDATE trigger fires only when the paid column is actually
--    changing (NEW.paid IS DISTINCT FROM OLD.paid) and raises an error if the
--    calling user is not manager or admin.  Normal sales editing by employees
--    (category, quantity, etc.) is unaffected because when paid is unchanged
--    the trigger condition is false and the trigger body never executes.
--
-- 2. Server-side default for sales.created_by
--    The frontend INSERT path always supplies created_by = auth.uid(), so the
--    column is populated in practice.  Adding a server-side DEFAULT auth.uid()
--    means that even if a future client-side insert ever omits the column, the
--    DB fills it in correctly — no data loss risk, purely additive.  This
--    prepares the ground for future ownership-based RLS (e.g. restrict UPDATE
--    to the row owner) without requiring immediate schema surgery.
--
-- What is intentionally deferred
-- ─────────────────────────────────────────────
-- • Adding NOT NULL to sales.created_by: the safest step is to first confirm
--   no NULL rows exist in production, then apply the constraint in a follow-on
--   migration.  Only the server-side DEFAULT is added here.
-- • Restricting sales UPDATE to row owners (created_by = auth.uid()):
--   Requires the NOT NULL guarantee to be reliable first, plus a careful review
--   of which roles can legitimately update which rows.  Deferred to pass 3B.
--
-- Rollout risks
-- ─────────────
-- • After applying this migration, any direct API call that attempts to change
--   sales.paid using an employee JWT will receive a DB error with ERRCODE
--   insufficient_privilege.  Legitimate UI usage is unaffected because:
--     – togglePaid() is already gated by hasPermission('tasks.toggle_paid')
--     – saveEditSale() sends paid in the update, but employees cannot change
--       the paid checkbox in the UI, so the value they send matches the
--       existing DB value (trigger condition = false, body never runs).
-- • The DEFAULT auth.uid() on created_by is a no-op for existing rows and
--   for any insert that already supplies created_by explicitly.  The only
--   visible effect is on inserts that omit created_by entirely, which do not
--   occur in the current codebase.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. Guard sales.paid: block direct-API changes by non-manager/non-admin ────

-- Trigger function: raises an error when paid is being changed by a user who
-- is not manager or admin.  SECURITY DEFINER with a pinned search_path prevents
-- search-path injection attacks.
CREATE OR REPLACE FUNCTION public.guard_sales_paid_update()
  RETURNS TRIGGER
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = public
AS $$
BEGIN
  -- Only enforce the check when the paid column is actually changing.
  -- This ensures normal employee sale edits (category, quantity, unit_price,
  -- etc.) are never blocked — only explicit attempts to flip paid trigger the
  -- check.
  IF NEW.paid IS DISTINCT FROM OLD.paid THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid()
        AND role IN ('manager', 'admin')
    ) THEN
      RAISE EXCEPTION
        'Permission refusée : modification du champ "payé" réservée aux managers et admins'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

-- Drop any existing version of the trigger before recreating it (idempotent).
DROP TRIGGER IF EXISTS check_sales_paid_update ON public.sales;

CREATE TRIGGER check_sales_paid_update
  BEFORE UPDATE ON public.sales
  FOR EACH ROW
  EXECUTE FUNCTION public.guard_sales_paid_update();


-- ── 2. Add server-side default for sales.created_by ──────────────────────────
-- auth.uid() evaluates to the UUID of the authenticated caller at insert time.
-- Non-breaking: existing rows are untouched, and existing inserts that already
-- supply created_by explicitly are unaffected.
ALTER TABLE public.sales
  ALTER COLUMN created_by SET DEFAULT auth.uid();
