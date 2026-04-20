-- ─────────────────────────────────────────────────────────────────────────────
-- role_permissions: configurable permissions per role (employee / manager)
-- admin is implicitly unrestricted and is NOT stored in this table.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.role_permissions (
  id             uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  role           text NOT NULL CHECK (role IN ('employee', 'manager')),
  permission_key text NOT NULL,
  allowed        boolean NOT NULL DEFAULT false,
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (role, permission_key)
);

ALTER TABLE public.role_permissions ENABLE ROW LEVEL SECURITY;

-- Any authenticated user can read permissions (needed to gate UI elements)
DROP POLICY IF EXISTS "role_permissions_select_auth" ON public.role_permissions;
CREATE POLICY "role_permissions_select_auth"
  ON public.role_permissions FOR SELECT
  TO authenticated
  USING (true);

-- Authenticated users can upsert / update permissions (app enforces admin-only)
DROP POLICY IF EXISTS "role_permissions_insert_auth" ON public.role_permissions;
CREATE POLICY "role_permissions_insert_auth"
  ON public.role_permissions FOR INSERT
  TO authenticated
  WITH CHECK (true);

DROP POLICY IF EXISTS "role_permissions_update_auth" ON public.role_permissions;
CREATE POLICY "role_permissions_update_auth"
  ON public.role_permissions FOR UPDATE
  TO authenticated
  USING (true)
  WITH CHECK (true);

DROP POLICY IF EXISTS "role_permissions_delete_auth" ON public.role_permissions;
CREATE POLICY "role_permissions_delete_auth"
  ON public.role_permissions FOR DELETE
  TO authenticated
  USING (true);

-- ── Default permission values ─────────────────────────────────────────────────
INSERT INTO public.role_permissions (role, permission_key, allowed) VALUES
  ('employee', 'tasks.create',      true),
  ('employee', 'tasks.edit',        true),
  ('employee', 'tasks.delete',      false),
  ('employee', 'tasks.toggle_paid', false),
  ('employee', 'clients.create',    false),
  ('employee', 'clients.edit',      false),
  ('employee', 'clients.delete',    false),
  ('employee', 'reports.view',      false),
  ('employee', 'stock.edit',        false),
  ('employee', 'users.view',        false),
  ('manager',  'tasks.create',      true),
  ('manager',  'tasks.edit',        true),
  ('manager',  'tasks.delete',      true),
  ('manager',  'tasks.toggle_paid', true),
  ('manager',  'clients.create',    true),
  ('manager',  'clients.edit',      true),
  ('manager',  'clients.delete',    true),
  ('manager',  'reports.view',      true),
  ('manager',  'stock.edit',        true),
  ('manager',  'users.view',        true)
ON CONFLICT (role, permission_key) DO NOTHING;
