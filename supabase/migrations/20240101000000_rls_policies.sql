-- ─────────────────────────────────────────────────────────────────────────────
-- RLS policies for TASKAFÉ
-- Tables: clients, sales, stocks, profiles
--
-- All authenticated users can read every table.
-- INSERT / UPDATE / DELETE on clients and sales is allowed to all authenticated
-- users (role checks are enforced at the app level via the profiles table).
-- stocks is similarly open to authenticated users so that offline sync can
-- replay upsert operations when the session is restored.
-- profiles SELECT is open to authenticated users; UPDATE is restricted to the
-- owner row so each user can only update their own profile.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Enable RLS on each table (idempotent) ────────────────────────────────────
ALTER TABLE IF EXISTS public.clients  ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.sales    ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.stocks   ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.profiles ENABLE ROW LEVEL SECURITY;

-- ── clients ──────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "clients_select_auth"  ON public.clients;
DROP POLICY IF EXISTS "clients_insert_auth"  ON public.clients;
DROP POLICY IF EXISTS "clients_update_auth"  ON public.clients;
DROP POLICY IF EXISTS "clients_delete_auth"  ON public.clients;

CREATE POLICY "clients_select_auth"
  ON public.clients FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "clients_insert_auth"
  ON public.clients FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "clients_update_auth"
  ON public.clients FOR UPDATE
  TO authenticated
  USING (true)
  WITH CHECK (true);

CREATE POLICY "clients_delete_auth"
  ON public.clients FOR DELETE
  TO authenticated
  USING (true);

-- ── sales ─────────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "sales_select_auth"  ON public.sales;
DROP POLICY IF EXISTS "sales_insert_auth"  ON public.sales;
DROP POLICY IF EXISTS "sales_update_auth"  ON public.sales;
DROP POLICY IF EXISTS "sales_delete_auth"  ON public.sales;

CREATE POLICY "sales_select_auth"
  ON public.sales FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "sales_insert_auth"
  ON public.sales FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "sales_update_auth"
  ON public.sales FOR UPDATE
  TO authenticated
  USING (true)
  WITH CHECK (true);

CREATE POLICY "sales_delete_auth"
  ON public.sales FOR DELETE
  TO authenticated
  USING (true);

-- ── stocks ────────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "stocks_select_auth"  ON public.stocks;
DROP POLICY IF EXISTS "stocks_upsert_auth"  ON public.stocks;
DROP POLICY IF EXISTS "stocks_insert_auth"  ON public.stocks;
DROP POLICY IF EXISTS "stocks_update_auth"  ON public.stocks;
DROP POLICY IF EXISTS "stocks_delete_auth"  ON public.stocks;

CREATE POLICY "stocks_select_auth"
  ON public.stocks FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "stocks_insert_auth"
  ON public.stocks FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "stocks_update_auth"
  ON public.stocks FOR UPDATE
  TO authenticated
  USING (true)
  WITH CHECK (true);

CREATE POLICY "stocks_delete_auth"
  ON public.stocks FOR DELETE
  TO authenticated
  USING (true);

-- ── profiles ──────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "profiles_select_auth"  ON public.profiles;
DROP POLICY IF EXISTS "profiles_update_own"   ON public.profiles;
DROP POLICY IF EXISTS "profiles_insert_own"   ON public.profiles;

CREATE POLICY "profiles_select_auth"
  ON public.profiles FOR SELECT
  TO authenticated
  USING (true);

-- Each user can only update their own profile row
CREATE POLICY "profiles_update_own"
  ON public.profiles FOR UPDATE
  TO authenticated
  USING (id = auth.uid())
  WITH CHECK (id = auth.uid());

-- Allow insert for new profile creation (e.g., trigger or first-boot)
CREATE POLICY "profiles_insert_own"
  ON public.profiles FOR INSERT
  TO authenticated
  WITH CHECK (id = auth.uid());
