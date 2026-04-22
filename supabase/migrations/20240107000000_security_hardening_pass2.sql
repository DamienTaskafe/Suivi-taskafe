-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Security hardening pass 2
-- ─────────────────────────────────────────────────────────────────────────────
-- Scope: conservative second pass — reduces direct-API bypass risks for
-- clients, stocks, and action_logs while keeping normal sales flows intact.
--
-- What this migration fixes
-- ─────────────────────────
-- 1. clients INSERT / UPDATE — previously open to any authenticated user.
--    The role_permissions table already declares that employees cannot create
--    or edit clients (clients.create = false, clients.edit = false), but that
--    guard was only enforced at the UI layer.  A user with an employee JWT
--    could bypass the frontend and write to clients via the REST API.
--    New policies restrict both operations to manager / admin at the DB level,
--    aligning the database with what the application already intends.
--
-- 2. stocks INSERT — previously open to any authenticated user.
--    Inserting a new stock category row (e.g. to introduce a ghost category)
--    is an admin-level operation.  Existing stock categories are updated (not
--    inserted) by the normal sales-flow upsert, so restricting INSERT to
--    manager / admin does not break any employee sales path.
--    stocks UPDATE is left open to all authenticated users because the
--    offline-sync replay logic (_executePendingOp → addSale / deleteSale)
--    calls supabase.from('stocks').upsert(...) on behalf of the employee who
--    created the sale.  Blocking that UPDATE would break the core sales flow.
--
-- 3. action_logs INSERT — previously WITH CHECK (true), meaning an
--    authenticated user could forge rows with an arbitrary user_id value (e.g.
--    attribute actions to another user).  The new policy enforces that the
--    user_id column must equal auth.uid(), preventing log-forging without
--    affecting the legitimate logAction() helper in index.html which already
--    sends user_id: state.session.user.id (= auth.uid()).
--
-- What is intentionally deferred
-- ─────────────────────────────────────────────
-- • sales INSERT / UPDATE are not tightened in this pass.
--   Employees have tasks.create = true and tasks.edit = true, meaning any
--   employee can legitimately add or edit a sale.  The offline-sync path also
--   replays sale inserts when the user reconnects.  Restricting sales writes to
--   manager / admin would break the primary business flow.  A future pass could
--   look at per-row ownership (e.g. created_by column) to restrict UPDATE to
--   the row owner, but that requires a schema change outside this scope.
--
-- Rollout risks
-- ─────────────
-- • After applying this migration, direct API calls that attempt to INSERT or
--   UPDATE a client row using an employee JWT will receive a 403 / RLS error.
--   Legitimate app usage is unaffected because the UI already prevents those
--   paths for employees.
-- • stocks INSERT is blocked for employees.  The upsert path (addSale /
--   deleteSale) targets existing categories and resolves to an UPDATE, so it
--   continues to work.  If a category row is missing (edge case: data loss or
--   brand-new deployment), an employee upsert will fail silently — the existing
--   console.warn already captures this.  A manager / admin must ensure all
--   category rows exist before going live.
-- • action_logs inserts where user_id IS NULL or user_id ≠ auth.uid() will now
--   be rejected.  The logAction() helper always passes auth.uid(), so normal
--   usage is unaffected.  Any other client-side code that omits user_id or
--   passes a different UUID will start failing — this is the intended outcome.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. Harden clients INSERT: restrict to manager / admin ────────────────────
DROP POLICY IF EXISTS "clients_insert_auth"          ON public.clients;
DROP POLICY IF EXISTS "clients_insert_manager_admin" ON public.clients;

-- Only managers and admins may add new client rows.  Employees have
-- clients.create = false in the role_permissions table; this policy enforces
-- the same constraint at the database level.
CREATE POLICY "clients_insert_manager_admin"
  ON public.clients FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('manager', 'admin')
    )
  );


-- ── 2. Harden clients UPDATE: restrict to manager / admin ────────────────────
DROP POLICY IF EXISTS "clients_update_auth"          ON public.clients;
DROP POLICY IF EXISTS "clients_update_manager_admin" ON public.clients;

-- Only managers and admins may edit existing client rows.  Employees have
-- clients.edit = false in the role_permissions table; this policy enforces
-- the same constraint at the database level.
CREATE POLICY "clients_update_manager_admin"
  ON public.clients FOR UPDATE
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


-- ── 3. Harden stocks INSERT: restrict to manager / admin ─────────────────────
DROP POLICY IF EXISTS "stocks_insert_auth"          ON public.stocks;
DROP POLICY IF EXISTS "stocks_insert_manager_admin" ON public.stocks;

-- Creating a new stock category row is an admin-level operation.  Employees
-- only need to UPDATE existing rows during the sales flow (via upsert).
-- Restricting INSERT prevents employees from injecting arbitrary categories
-- via direct API calls without affecting the normal addSale / deleteSale path,
-- which performs an upsert on a category that already exists (→ UPDATE).
CREATE POLICY "stocks_insert_manager_admin"
  ON public.stocks FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('manager', 'admin')
    )
  );

-- stocks UPDATE is intentionally left open to all authenticated users.
-- See the header comment for the rationale (employee sales-flow upsert path).


-- ── 4. Harden action_logs INSERT: enforce user_id = auth.uid() ───────────────
DROP POLICY IF EXISTS "action_logs_insert_auth"            ON public.action_logs;
DROP POLICY IF EXISTS "action_logs_insert_own_user_id"     ON public.action_logs;

-- Prevent log-forging: the user_id column must match the JWT identity of the
-- caller.  The logAction() helper in index.html already sends
-- user_id: state.session.user.id which equals auth.uid(), so legitimate
-- inserts are unaffected.  Any attempt to attribute a log row to a different
-- user will be rejected at the DB level.
CREATE POLICY "action_logs_insert_own_user_id"
  ON public.action_logs FOR INSERT
  TO authenticated
  WITH CHECK (user_id = auth.uid());
