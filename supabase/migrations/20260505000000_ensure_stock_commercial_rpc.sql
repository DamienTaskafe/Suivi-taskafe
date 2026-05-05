-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Ensure stock commercial RPC functions (idempotent)
-- ─────────────────────────────────────────────────────────────────────────────
-- This migration is safe to apply multiple times (idempotent).
-- It guarantees the following objects exist even when a previous migration was
-- not fully applied or when the PostgREST schema cache is stale:
--
--   1. public.stock_commercial  (table)
--   2. public.stock_movements   (table)
--   3. public.transfer_stock_to_commercial(uuid, text, numeric)
--   4. public.return_stock_from_commercial(uuid, text, numeric)
--
-- After applying this migration, if PostgREST still reports the function as
-- absent, reload the schema cache in the Supabase dashboard:
--   Settings → API → Reload schema cache
-- or restart/reload the Supabase API service.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── 1. stock_commercial table ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.stock_commercial (
  user_id    uuid    NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  category   text    NOT NULL,
  quantity   numeric NOT NULL DEFAULT 0 CHECK (quantity >= 0),
  PRIMARY KEY (user_id, category)
);

ALTER TABLE public.stock_commercial ENABLE ROW LEVEL SECURITY;

-- ── 2. stock_movements table ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.stock_movements (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  movement_type text        NOT NULL,
  employee_id   uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  category      text        NOT NULL,
  quantity      numeric     NOT NULL,
  notes         text,
  created_by    uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.stock_movements ENABLE ROW LEVEL SECURITY;

-- ── 3. RLS policies (idempotent: drop then recreate) ─────────────────────────

-- stock_commercial: employees see their own row; admins/managers see all.
DROP POLICY IF EXISTS "stock_commercial_select" ON public.stock_commercial;
CREATE POLICY "stock_commercial_select"
  ON public.stock_commercial FOR SELECT
  TO authenticated
  USING (
    user_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

DROP POLICY IF EXISTS "stock_commercial_insert_admin" ON public.stock_commercial;
CREATE POLICY "stock_commercial_insert_admin"
  ON public.stock_commercial FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

DROP POLICY IF EXISTS "stock_commercial_update_admin" ON public.stock_commercial;
CREATE POLICY "stock_commercial_update_admin"
  ON public.stock_commercial FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

DROP POLICY IF EXISTS "stock_commercial_delete_admin" ON public.stock_commercial;
CREATE POLICY "stock_commercial_delete_admin"
  ON public.stock_commercial FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

-- stock_movements: employee sees movements involving them; admins/managers see all.
DROP POLICY IF EXISTS "stock_movements_select" ON public.stock_movements;
CREATE POLICY "stock_movements_select"
  ON public.stock_movements FOR SELECT
  TO authenticated
  USING (
    employee_id = auth.uid()
    OR created_by = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

DROP POLICY IF EXISTS "stock_movements_insert" ON public.stock_movements;
CREATE POLICY "stock_movements_insert"
  ON public.stock_movements FOR INSERT
  TO authenticated
  WITH CHECK (true);

-- ── 4. transfer_stock_to_commercial() ────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.transfer_stock_to_commercial(
  p_employee_id uuid,
  p_category    text,
  p_quantity    numeric
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  central_qty numeric;
BEGIN
  -- Permission check: only admins and managers may transfer stock.
  IF NOT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND role IN ('admin', 'manager')
  ) THEN
    RAISE EXCEPTION 'PERMISSION_DENIED: transfert réservé aux admins et managers';
  END IF;

  IF p_quantity <= 0 THEN
    RAISE EXCEPTION 'QUANTITE_INVALIDE: la quantité doit être positive (reçu: %)', p_quantity;
  END IF;

  -- Seed central stock row if absent so the UPDATE below always has a row to lock.
  INSERT INTO public.stocks (category, quantity)
    VALUES (p_category, 0)
    ON CONFLICT (category) DO NOTHING;

  -- Atomically deduct from central stock; non-negative guard.
  UPDATE public.stocks
    SET quantity = quantity - p_quantity
    WHERE category = p_category AND quantity >= p_quantity;

  IF NOT FOUND THEN
    SELECT quantity INTO central_qty FROM public.stocks WHERE category = p_category;
    RAISE EXCEPTION 'STOCK_CENTRAL_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
      p_category, p_quantity, COALESCE(central_qty, 0);
  END IF;

  -- Upsert commercial stock row for the employee (create row if first transfer).
  INSERT INTO public.stock_commercial (user_id, category, quantity)
    VALUES (p_employee_id, p_category, p_quantity)
    ON CONFLICT (user_id, category)
    DO UPDATE SET quantity = public.stock_commercial.quantity + p_quantity;

  -- Audit trail.
  INSERT INTO public.stock_movements (movement_type, employee_id, category, quantity, created_by)
    VALUES ('central_to_commercial', p_employee_id, p_category, p_quantity, auth.uid());
END;
$$;

REVOKE EXECUTE ON FUNCTION public.transfer_stock_to_commercial(uuid, text, numeric) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.transfer_stock_to_commercial(uuid, text, numeric) TO authenticated;


-- ── 5. return_stock_from_commercial() ────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.return_stock_from_commercial(
  p_employee_id uuid,
  p_category    text,
  p_quantity    numeric
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  commercial_qty numeric;
BEGIN
  -- Permission check: only admins and managers may recover stock.
  IF NOT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND role IN ('admin', 'manager')
  ) THEN
    RAISE EXCEPTION 'PERMISSION_DENIED: récupération réservée aux admins et managers';
  END IF;

  IF p_quantity <= 0 THEN
    RAISE EXCEPTION 'QUANTITE_INVALIDE: la quantité doit être positive (reçu: %)', p_quantity;
  END IF;

  -- Atomically deduct from commercial stock; non-negative guard.
  UPDATE public.stock_commercial
    SET quantity = quantity - p_quantity
    WHERE user_id = p_employee_id AND category = p_category AND quantity >= p_quantity;

  IF NOT FOUND THEN
    SELECT quantity INTO commercial_qty
      FROM public.stock_commercial
      WHERE user_id = p_employee_id AND category = p_category;
    RAISE EXCEPTION 'STOCK_COMMERCIAL_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
      p_category, p_quantity, COALESCE(commercial_qty, 0);
  END IF;

  -- Add back to central stock.
  INSERT INTO public.stocks (category, quantity)
    VALUES (p_category, p_quantity)
    ON CONFLICT (category)
    DO UPDATE SET quantity = public.stocks.quantity + p_quantity;

  -- Audit trail.
  INSERT INTO public.stock_movements (movement_type, employee_id, category, quantity, created_by)
    VALUES ('commercial_to_central', p_employee_id, p_category, p_quantity, auth.uid());
END;
$$;

REVOKE EXECUTE ON FUNCTION public.return_stock_from_commercial(uuid, text, numeric) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.return_stock_from_commercial(uuid, text, numeric) TO authenticated;
