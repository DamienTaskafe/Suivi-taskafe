-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Align client RLS with configurable role permissions
-- ─────────────────────────────────────────────────────────────────────────────
-- Problem fixed
-- ─────────────
-- The app exposes configurable permissions (role_permissions) such as:
--   • clients.create
--   • clients.edit
--   • clients.delete
--
-- But an earlier hardening migration restricted clients INSERT/UPDATE/DELETE to
-- manager/admin only at the database level. Result: when an admin enables client
-- creation for employees/commercials in the UI, Supabase RLS can still block the
-- action.
--
-- This migration makes the DB layer follow the same permission matrix:
--   • admin: unrestricted on clients
--   • manager/employee: allowed only when role_permissions says so
--   • non-admin users creating/updating clients must keep ownership scoped to
--     themselves (assigned_user_id = auth.uid()) unless they are manager/admin
--
-- Business default: commercials should be able to create their own clients, so
-- clients.create is enabled for employee by default. Admin can still disable it
-- later from the permissions panel.
-- ─────────────────────────────────────────────────────────────────────────────

-- Ensure permission rows exist and set the intended business default.
INSERT INTO public.role_permissions (role, permission_key, allowed)
VALUES
  ('employee', 'clients.create', true),
  ('employee', 'clients.edit',   true),
  ('manager',  'clients.create', true),
  ('manager',  'clients.edit',   true),
  ('manager',  'clients.delete', true)
ON CONFLICT (role, permission_key)
DO UPDATE SET
  allowed = EXCLUDED.allowed,
  updated_at = now();

-- Helper: true when current authenticated user is admin.
CREATE OR REPLACE FUNCTION public.is_current_user_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.profiles p
    WHERE p.id = auth.uid()
      AND p.role = 'admin'
  );
$$;

-- Helper: true when current authenticated user has a configurable permission.
-- Admin is implicitly unrestricted and does not need role_permissions rows.
CREATE OR REPLACE FUNCTION public.current_user_has_permission(p_permission_key text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.profiles p
    WHERE p.id = auth.uid()
      AND p.role = 'admin'
  )
  OR EXISTS (
    SELECT 1
    FROM public.profiles p
    JOIN public.role_permissions rp
      ON rp.role = p.role
     AND rp.permission_key = p_permission_key
     AND rp.allowed = true
    WHERE p.id = auth.uid()
  );
$$;

-- Helper: true when current user is manager/admin.
CREATE OR REPLACE FUNCTION public.is_current_user_manager_or_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.profiles p
    WHERE p.id = auth.uid()
      AND p.role IN ('admin', 'manager')
  );
$$;

-- Rebuild clients policies to align with permissions.
DROP POLICY IF EXISTS "clients_insert_auth" ON public.clients;
DROP POLICY IF EXISTS "clients_insert_manager_admin" ON public.clients;
DROP POLICY IF EXISTS "clients_insert_permission_scoped" ON public.clients;

CREATE POLICY "clients_insert_permission_scoped"
  ON public.clients FOR INSERT
  TO authenticated
  WITH CHECK (
    public.current_user_has_permission('clients.create')
    AND (
      -- Managers/admins may create unassigned clients or assign them.
      public.is_current_user_manager_or_admin()
      -- Employees/commercials may create only their own assigned clients.
      OR assigned_user_id = auth.uid()
    )
  );

DROP POLICY IF EXISTS "clients_update_auth" ON public.clients;
DROP POLICY IF EXISTS "clients_update_manager_admin" ON public.clients;
DROP POLICY IF EXISTS "clients_update_permission_scoped" ON public.clients;

CREATE POLICY "clients_update_permission_scoped"
  ON public.clients FOR UPDATE
  TO authenticated
  USING (
    public.current_user_has_permission('clients.edit')
    AND (
      public.is_current_user_manager_or_admin()
      OR assigned_user_id = auth.uid()
    )
  )
  WITH CHECK (
    public.current_user_has_permission('clients.edit')
    AND (
      -- Managers/admins may reassign clients to anyone or leave unassigned.
      public.is_current_user_manager_or_admin()
      -- Employees/commercials may only keep the client assigned to themselves.
      OR assigned_user_id = auth.uid()
    )
  );

DROP POLICY IF EXISTS "clients_delete_auth" ON public.clients;
DROP POLICY IF EXISTS "clients_delete_manager_admin" ON public.clients;
DROP POLICY IF EXISTS "clients_delete_permission_scoped" ON public.clients;

CREATE POLICY "clients_delete_permission_scoped"
  ON public.clients FOR DELETE
  TO authenticated
  USING (
    public.current_user_has_permission('clients.delete')
    AND (
      public.is_current_user_manager_or_admin()
      OR assigned_user_id = auth.uid()
    )
  );

-- Keep SELECT open as before; the app scopes employees to assigned/unassigned
-- clients in loadCloudData(). Recreate only if a previous environment lost it.
DROP POLICY IF EXISTS "clients_select_auth" ON public.clients;
CREATE POLICY "clients_select_auth"
  ON public.clients FOR SELECT
  TO authenticated
  USING (true);
