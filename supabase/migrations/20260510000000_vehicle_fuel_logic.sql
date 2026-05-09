-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Vehicle fuel declarations + fuel advances
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.vehicles (
  id                           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  registration                 text        NOT NULL UNIQUE,
  assigned_employee_id         uuid        NULL REFERENCES public.profiles(id) ON DELETE SET NULL,
  normal_consumption_l100      numeric     NULL CHECK (normal_consumption_l100 >= 0),
  consumption_tolerance_l100   numeric     NULL CHECK (consumption_tolerance_l100 >= 0),
  maintenance_interval_km      integer     NULL CHECK (maintenance_interval_km >= 0),
  last_maintenance_km          integer     NULL CHECK (last_maintenance_km >= 0),
  current_km                   integer     NULL CHECK (current_km >= 0),
  is_active                    boolean     NOT NULL DEFAULT true,
  created_by                   uuid        NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at                   timestamptz NOT NULL DEFAULT now(),
  updated_at                   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.fuel_declarations (
  id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  employee_id           uuid        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  vehicle_id            uuid        NULL REFERENCES public.vehicles(id) ON DELETE SET NULL,
  vehicle_registration  text        NULL,
  declared_at           timestamptz NOT NULL DEFAULT now(),
  current_km            integer     NOT NULL CHECK (current_km >= 0),
  liters                numeric     NOT NULL CHECK (liters > 0),
  amount                numeric     NOT NULL CHECK (amount >= 0),
  receipt_photo_url     text        NULL,
  comment               text        NULL,
  status                text        NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending', 'validated', 'rejected', 'paid_in_payroll')),
  consumption_l100      numeric     NULL CHECK (consumption_l100 >= 0),
  consumption_alert     boolean     NOT NULL DEFAULT false,
  validation_note       text        NULL,
  validated_by          uuid        NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  validated_at          timestamptz NULL,
  paid_in_payroll_at    timestamptz NULL,
  created_by            uuid        NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.employee_balance_entries
  ADD COLUMN IF NOT EXISTS advance_category text NULL
    CHECK (advance_category IS NULL OR advance_category IN ('salary', 'fuel', 'other'));

CREATE INDEX IF NOT EXISTS fuel_declarations_employee_declared_idx
  ON public.fuel_declarations (employee_id, declared_at DESC);
CREATE INDEX IF NOT EXISTS fuel_declarations_vehicle_declared_idx
  ON public.fuel_declarations (vehicle_id, declared_at DESC);
CREATE INDEX IF NOT EXISTS fuel_declarations_status_idx
  ON public.fuel_declarations (status, declared_at DESC);

CREATE INDEX IF NOT EXISTS vehicles_assigned_employee_idx
  ON public.vehicles (assigned_employee_id);

CREATE OR REPLACE FUNCTION public.tg_set_vehicles_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_vehicles_updated_at ON public.vehicles;
CREATE TRIGGER trg_vehicles_updated_at
BEFORE UPDATE ON public.vehicles
FOR EACH ROW
EXECUTE FUNCTION public.tg_set_vehicles_updated_at();

CREATE OR REPLACE FUNCTION public.tg_set_fuel_declarations_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_fuel_declarations_updated_at ON public.fuel_declarations;
CREATE TRIGGER trg_fuel_declarations_updated_at
BEFORE UPDATE ON public.fuel_declarations
FOR EACH ROW
EXECUTE FUNCTION public.tg_set_fuel_declarations_updated_at();

ALTER TABLE public.vehicles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fuel_declarations ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "vehicles_select" ON public.vehicles;
CREATE POLICY "vehicles_select"
  ON public.vehicles FOR SELECT
  TO authenticated
  USING (
    public.is_admin_or_manager()
    OR assigned_employee_id = auth.uid()
  );

DROP POLICY IF EXISTS "vehicles_insert" ON public.vehicles;
CREATE POLICY "vehicles_insert"
  ON public.vehicles FOR INSERT
  TO authenticated
  WITH CHECK (public.is_admin_or_manager());

DROP POLICY IF EXISTS "vehicles_update" ON public.vehicles;
CREATE POLICY "vehicles_update"
  ON public.vehicles FOR UPDATE
  TO authenticated
  USING (public.is_admin_or_manager())
  WITH CHECK (public.is_admin_or_manager());

DROP POLICY IF EXISTS "vehicles_delete" ON public.vehicles;
CREATE POLICY "vehicles_delete"
  ON public.vehicles FOR DELETE
  TO authenticated
  USING (public.is_admin_or_manager());

DROP POLICY IF EXISTS "fuel_declarations_select" ON public.fuel_declarations;
CREATE POLICY "fuel_declarations_select"
  ON public.fuel_declarations FOR SELECT
  TO authenticated
  USING (
    employee_id = auth.uid()
    OR public.is_admin_or_manager()
  );

DROP POLICY IF EXISTS "fuel_declarations_insert" ON public.fuel_declarations;
CREATE POLICY "fuel_declarations_insert"
  ON public.fuel_declarations FOR INSERT
  TO authenticated
  WITH CHECK (
    employee_id = auth.uid()
    OR public.is_admin_or_manager()
  );

DROP POLICY IF EXISTS "fuel_declarations_update" ON public.fuel_declarations;
CREATE POLICY "fuel_declarations_update"
  ON public.fuel_declarations FOR UPDATE
  TO authenticated
  USING (public.is_admin_or_manager())
  WITH CHECK (public.is_admin_or_manager());

DROP POLICY IF EXISTS "fuel_declarations_delete" ON public.fuel_declarations;
CREATE POLICY "fuel_declarations_delete"
  ON public.fuel_declarations FOR DELETE
  TO authenticated
  USING (public.is_admin_or_manager());

NOTIFY pgrst, 'reload schema';
