-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Security hardening pass 3B — sales ownership enforcement
-- ─────────────────────────────────────────────────────────────────────────────
-- Scope: targeted low-risk hardening that builds directly on pass 3A.
-- Two concerns addressed here; both are independent and safe to roll back
-- individually.
--
-- What this migration does
-- ─────────────────────────
-- 1. Enforce NOT NULL on sales.created_by
--    Pass 3A added a server-side DEFAULT auth.uid() so that all new inserts
--    populate the column.  The offline replay fix (applied after 3A) ensures
--    the client no longer sends created_by = null explicitly.  Production has
--    been verified to contain zero NULL values:
--
--      select count(*) as null_created_by_count
--      from sales where created_by is null;  -- Result: 0
--
--    It is now safe to promote the column from nullable to NOT NULL.
--
-- 2. Ownership-based UPDATE policy for sales
--    The previous policy ("sales_update_auth") allowed any authenticated user
--    to update any sale row via the REST API, bypassing the UI-level ownership
--    check.  The new policy enforces the same rule at the database level:
--      • Employees (role = 'employee') may only update rows where
--        created_by = auth.uid() — their own sales.
--      • Managers and admins may update any sale row.
--    The paid-column guard (trigger check_sales_paid_update, added in pass 3A)
--    continues to fire independently and is unaffected by this change.
--
-- What is intentionally deferred
-- ─────────────────────────────────────────────
-- • stocks client-side writes: still handled by the client for the
--   addSale / deleteSale / saveEditSale flows.  Moving those to a DB trigger
--   is planned for a later pass (3C) and is out of scope here.
-- • stocks UPDATE RLS tightening: deferred until after pass 3C removes
--   the employee sales-flow upsert path (pass 2 rationale still applies).
--
-- Rollout risks
-- ─────────────
-- • After applying this migration, any direct API call that attempts to UPDATE
--   a sale row where created_by ≠ auth.uid() using an employee JWT will be
--   rejected silently by RLS (the row will simply not match and no rows will
--   be updated).  Managers and admins retain full UPDATE access.
-- • The NOT NULL constraint is safe because production contains zero NULL rows
--   and all current insert paths populate created_by.  If this migration is
--   ever run against a copy of the database that still has NULLs, the
--   ALTER TABLE statement will fail with a NOT NULL constraint violation —
--   the correct outcome (do not apply until NULLs are resolved).
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. Enforce NOT NULL on sales.created_by ──────────────────────────────────
-- Production confirmed: 0 NULL rows exist.
-- Pass 3A added DEFAULT auth.uid(); the offline fix prevents explicit NULLs.
ALTER TABLE public.sales
  ALTER COLUMN created_by SET NOT NULL;


-- ── 2. Ownership-based UPDATE policy for sales ───────────────────────────────
-- Drop the previous open policy and any prior draft of the ownership policy.
DROP POLICY IF EXISTS "sales_update_auth"                 ON public.sales;
DROP POLICY IF EXISTS "sales_update_owner_or_manager"     ON public.sales;

-- Employees can update only their own sales (created_by = auth.uid()).
-- Managers and admins can update any sale.
-- The paid-column trigger (check_sales_paid_update) coexists correctly:
--   • An employee updating their own sale still hits the trigger if they
--     attempt to change the paid column (correctly blocked).
--   • A manager updating any sale is also subject to the trigger only when
--     paid actually changes (intended behaviour, unchanged from pass 3A).
CREATE POLICY "sales_update_owner_or_manager"
  ON public.sales FOR UPDATE
  TO authenticated
  USING (
    created_by = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid()
        AND role IN ('manager', 'admin')
    )
  )
  WITH CHECK (
    created_by = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid()
        AND role IN ('manager', 'admin')
    )
  );
