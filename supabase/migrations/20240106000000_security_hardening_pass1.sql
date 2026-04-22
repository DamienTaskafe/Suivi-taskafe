-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Security hardening pass 1
-- ─────────────────────────────────────────────────────────────────────────────
-- Scope: minimal, low-risk hardening of confirmed privilege-escalation and
-- direct-API permission-bypass risks.
--
-- What this migration fixes
-- ─────────────────────────
-- 1. Self-role escalation via profiles UPDATE
--    The previous profiles_update_own policy allowed an authenticated user to
--    update any column on their own profile row, including the role column.
--    Any user could therefore do:
--      UPDATE profiles SET role = 'admin' WHERE id = auth.uid()
--    and silently self-promote.  The new policy adds a WITH CHECK subquery that
--    verifies the role value in the proposed new row matches the current stored
--    role, making it impossible to change role via a normal client-side update.
--    The service_role key (used by api/update-role.js) bypasses RLS entirely,
--    so admin-triggered role changes are unaffected.
--
-- 2. Self-role injection via profiles INSERT
--    The previous profiles_insert_own policy allowed authenticated users to
--    insert their own profile row with an arbitrary role value.  The new policy
--    restricts the role to 'employee' on client-facing inserts.  Server-side
--    functions (api/create-user.js, the on_auth_user_created trigger) use the
--    service_role key and are unaffected.
--
-- 3. Unrestricted DELETE on clients / sales / stocks
--    All three tables previously allowed any authenticated user to delete any
--    row.  App-level permission checks (hasPermission / role checks) were the
--    only guard, which can be bypassed via a direct Supabase API call.  The new
--    policies enforce the same manager/admin restriction at the DB level.
--
-- What is intentionally deferred (second pass)
-- ─────────────────────────────────────────────
-- • INSERT and UPDATE on clients/sales/stocks are left open to all
--   authenticated users.  Tightening those requires careful review of the
--   offline-sync replay logic (_executePendingOp) and the role_permissions
--   matrix to avoid breaking normal employee sales flows.
-- • The action_logs INSERT policy (currently open to all authenticated users)
--   is deferred pending a review of which events non-admin users need to log.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. Harden profiles UPDATE: block self-role escalation ────────────────────
DROP POLICY IF EXISTS "profiles_update_own" ON public.profiles;

-- A user may only update their own row AND the proposed new role must equal
-- the role currently stored in the database.  This prevents self-promotion
-- while still allowing updates to every other profile column (full_name, etc.).
-- The service_role key used by api/update-role.js bypasses RLS completely, so
-- admin-initiated role changes continue to work without modification.
CREATE POLICY "profiles_update_own"
  ON public.profiles FOR UPDATE
  TO authenticated
  USING  (id = auth.uid())
  WITH CHECK (
    id = auth.uid()
    AND role = (SELECT role FROM public.profiles WHERE id = auth.uid())
  );


-- ── 2. Harden profiles INSERT: block elevated-role injection ─────────────────
DROP POLICY IF EXISTS "profiles_insert_own" ON public.profiles;

-- Client-facing inserts (e.g., first-boot edge cases) are restricted to the
-- default 'employee' role.  The on_auth_user_created trigger and
-- api/create-user.js both use service_role and bypass this policy.
CREATE POLICY "profiles_insert_own"
  ON public.profiles FOR INSERT
  TO authenticated
  WITH CHECK (id = auth.uid() AND role = 'employee');


-- ── 3. Restrict DELETE on clients to manager / admin ─────────────────────────
DROP POLICY IF EXISTS "clients_delete_auth"          ON public.clients;
DROP POLICY IF EXISTS "clients_delete_manager_admin" ON public.clients;

CREATE POLICY "clients_delete_manager_admin"
  ON public.clients FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('manager', 'admin')
    )
  );


-- ── 4. Restrict DELETE on sales to manager / admin ───────────────────────────
DROP POLICY IF EXISTS "sales_delete_auth"          ON public.sales;
DROP POLICY IF EXISTS "sales_delete_manager_admin" ON public.sales;

CREATE POLICY "sales_delete_manager_admin"
  ON public.sales FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('manager', 'admin')
    )
  );


-- ── 5. Restrict DELETE on stocks to manager / admin ──────────────────────────
-- INSERT and UPDATE on stocks remain open to all authenticated users so that
-- the offline-sync upsert path (used when replaying pending sale operations)
-- continues to work for employees.
DROP POLICY IF EXISTS "stocks_delete_auth"          ON public.stocks;
DROP POLICY IF EXISTS "stocks_delete_manager_admin" ON public.stocks;

CREATE POLICY "stocks_delete_manager_admin"
  ON public.stocks FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('manager', 'admin')
    )
  );
