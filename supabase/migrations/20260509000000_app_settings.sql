-- ── app_settings: generic key-value store for admin/manager settings ─────────
-- Stores JSON blobs keyed by a string identifier.
-- Used to persist wholesale purchases, payments, settings and product purchase
-- prices in the cloud so that admin/manager data is shared across devices.
-- Idempotent migration: safe to run multiple times.

CREATE TABLE IF NOT EXISTS public.app_settings (
  key        text        PRIMARY KEY,
  value      jsonb       NOT NULL DEFAULT 'null',
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.app_settings ENABLE ROW LEVEL SECURITY;

-- ── RLS policies — admin/manager only ────────────────────────────────────────

DROP POLICY IF EXISTS "app_settings_select_admin_manager" ON public.app_settings;
CREATE POLICY "app_settings_select_admin_manager"
  ON public.app_settings FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

DROP POLICY IF EXISTS "app_settings_insert_admin_manager" ON public.app_settings;
CREATE POLICY "app_settings_insert_admin_manager"
  ON public.app_settings FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

DROP POLICY IF EXISTS "app_settings_update_admin_manager" ON public.app_settings;
CREATE POLICY "app_settings_update_admin_manager"
  ON public.app_settings FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

GRANT SELECT, INSERT, UPDATE ON public.app_settings TO authenticated;
