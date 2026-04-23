-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Security hardening pass 3D — tighten stocks UPDATE to manager/admin
-- ─────────────────────────────────────────────────────────────────────────────
-- Scope: Replace the broad "any authenticated user may UPDATE stocks" policy
-- that was intentionally deferred in pass 2 with a policy that restricts
-- direct UPDATE access to manager and admin roles only.
--
-- Why this is now safe
-- ─────────────────────
-- Pass 2 left stocks UPDATE open because the employee sales flow called
-- supabase.from('stocks').upsert(...) directly from the client for both the
-- online path and the offline-sync replay.  Blocking that UPDATE would have
-- broken addSale / deleteSale / saveEditSale for employees.
--
-- Pass 3C (merged before this migration) moved all sales-driven stock
-- adjustments to an AFTER-row-level trigger (trg_sales_adjust_stock) on
-- public.sales.  That trigger runs as SECURITY DEFINER, so it bypasses RLS and
-- does not require the calling user to have UPDATE permission on public.stocks.
-- The client-side stocks.upsert() calls that accompanied every sale mutation
-- were also removed from index.html in pass 3C.
--
-- As a result:
-- • Employees no longer need direct UPDATE access on public.stocks for any
--   normal business operation.
-- • Manager / admin users retain direct UPDATE access for manual stock
--   management (addToStock, setStock) which is the intended behaviour.
-- • Sales-driven stock changes continue to work through the DB trigger without
--   any RLS permission requirement on the caller.
--
-- What this migration does
-- ─────────────────────────
-- 1. Drops the broad "stocks_update_auth" policy (open to all authenticated
--    users) that was created in the initial RLS migration and left untouched
--    in passes 1, 2, 3A, 3B, and 3C.
-- 2. Creates "stocks_update_manager_admin", which allows UPDATE only for users
--    whose row in public.profiles has role = 'manager' or role = 'admin'.
--
-- Unchanged
-- ──────────
-- • stocks SELECT policy remains open to all authenticated users.
-- • stocks INSERT policy (manager / admin only, from pass 2) is untouched.
-- • stocks DELETE policy is untouched.
-- • No other tables, triggers, or UI logic are changed.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── Tighten stocks UPDATE: restrict to manager / admin ───────────────────────
DROP POLICY IF EXISTS "stocks_update_auth"          ON public.stocks;
DROP POLICY IF EXISTS "stocks_update_manager_admin" ON public.stocks;

-- Only managers and admins may directly update stock rows.  Employees no
-- longer need this permission because sales-driven adjustments are handled
-- atomically by the trg_sales_adjust_stock trigger (SECURITY DEFINER) added
-- in pass 3C.  Manual stock management (addToStock, setStock) is a
-- manager / admin operation and continues to work correctly.
CREATE POLICY "stocks_update_manager_admin"
  ON public.stocks FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('manager', 'admin')
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('manager', 'admin')
    )
  );
