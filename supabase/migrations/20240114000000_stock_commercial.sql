-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Commercial stock foundation
-- ─────────────────────────────────────────────────────────────────────────────
-- Business context
-- ─────────────────
-- The business maintains a central stock managed by the admin.  Each employee
-- (sales rep) is given a portion of that central stock as a personal
-- "mini-stock" (carried in their vehicle).  Sales by employees decrement only
-- their own commercial stock, never the central pool.  Admins can transfer
-- stock to employees, and recover it when needed.
--
-- What this migration adds
-- ─────────────────────────
-- 1. public.stock_commercial  — per-employee, per-category stock quantities.
--    When a row exists for (user_id, category), sales created by that user
--    consume from this commercial stock rather than the central public.stocks.
--    A CHECK constraint keeps quantity >= 0 at all times.
--
-- 2. public.stock_movements — append-only audit log for all stock transfers
--    between central and commercial pools.
--
-- 3. RLS policies on both new tables:
--    • stock_commercial: employees read their own row; admins/managers read all.
--      All writes go through SECURITY DEFINER functions, so direct DML is
--      restricted to admins/managers via RLS policies as an extra guard.
--    • stock_movements: employees see movements that involve them (employee_id);
--      admins/managers see all; authenticated users may insert.
--
-- 4. transfer_stock_to_commercial(employee_id, category, quantity)
--    SECURITY DEFINER function (runs as DB owner).  Atomically:
--      a) Deducts from central public.stocks (non-negative guard).
--      b) Upserts into stock_commercial for the named employee.
--      c) Inserts an audit row into stock_movements.
--    Raises PERMISSION_DENIED when the caller is not admin or manager.
--
-- 5. return_stock_from_commercial(employee_id, category, quantity)
--    SECURITY DEFINER function.  Atomically:
--      a) Deducts from stock_commercial (non-negative guard).
--      b) Adds back to central public.stocks.
--      c) Inserts an audit row into stock_movements.
--    Raises PERMISSION_DENIED when the caller is not admin or manager.
--
-- 6. Updated adjust_stock_on_sale_change() trigger — replaces the version
--    installed by the stock_nonneg_guard migration.  For each INSERT / DELETE /
--    UPDATE on public.sales it now routes the stock adjustment:
--      • When NEW.created_by has a stock_commercial row for NEW.category
--        → deducts from / restores to stock_commercial (non-negative guard).
--      • Otherwise (NULL created_by, or no commercial row for that category)
--        → deducts from / restores to central public.stocks (legacy path,
--           fully backward-compatible).
--
-- Compatibility guarantees
-- ─────────────────────────
-- • Existing sales and stock values are untouched.
-- • Employees who have never been given commercial stock have no rows in
--   stock_commercial; their sales continue to hit the central pool exactly
--   as before — zero disruption to the current workflow.
-- • All new columns/tables use DEFAULT-safe or nullable patterns so a fresh
--   environment (e.g. new Supabase project) works with a single migration run.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. stock_commercial table ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.stock_commercial (
  user_id   uuid    NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  category  text    NOT NULL,
  quantity  numeric NOT NULL DEFAULT 0 CHECK (quantity >= 0),
  PRIMARY KEY (user_id, category)
);

ALTER TABLE public.stock_commercial ENABLE ROW LEVEL SECURITY;


-- ── 2. stock_movements audit table ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.stock_movements (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  -- 'central_to_commercial' | 'commercial_to_central'
  movement_type text        NOT NULL,
  employee_id   uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  category      text        NOT NULL,
  quantity      numeric     NOT NULL,
  notes         text,
  created_by    uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.stock_movements ENABLE ROW LEVEL SECURITY;


-- ── 3. RLS policies ───────────────────────────────────────────────────────────

-- stock_commercial ----------------------------------------------------------

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

-- Direct INSERT / UPDATE / DELETE are restricted to admins/managers.
-- Normal mutations happen through SECURITY DEFINER functions; these policies
-- act as an additional defence-in-depth guard.

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
  )
  WITH CHECK (true);

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

-- stock_movements -----------------------------------------------------------

DROP POLICY IF EXISTS "stock_movements_select" ON public.stock_movements;
CREATE POLICY "stock_movements_select"
  ON public.stock_movements FOR SELECT
  TO authenticated
  USING (
    employee_id = auth.uid()
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


-- ── 6. Updated adjust_stock_on_sale_change() trigger ─────────────────────────
-- Replaces the version from the stock_nonneg_guard migration.  Now routes
-- stock adjustments through stock_commercial when applicable.

CREATE OR REPLACE FUNCTION public.adjust_stock_on_sale_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  current_qty    numeric;
  use_commercial boolean;
BEGIN
  -- ── INSERT: new sale consumes stock ─────────────────────────────────────────
  IF TG_OP = 'INSERT' THEN
    -- Commercial stock is used when the selling user has a stock_commercial row
    -- for this category.  Row presence opts the user into commercial-stock mode;
    -- absence falls back to the central stock pool (backward-compatible).
    use_commercial := (
      NEW.created_by IS NOT NULL AND
      EXISTS (
        SELECT 1 FROM public.stock_commercial
        WHERE user_id = NEW.created_by AND category = NEW.category
      )
    );

    IF use_commercial THEN
      UPDATE public.stock_commercial
        SET quantity = quantity - NEW.quantity
        WHERE user_id = NEW.created_by
          AND category = NEW.category
          AND quantity >= NEW.quantity;
      IF NOT FOUND THEN
        SELECT quantity INTO current_qty
          FROM public.stock_commercial
          WHERE user_id = NEW.created_by AND category = NEW.category;
        RAISE EXCEPTION 'STOCK_COMMERCIAL_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
          NEW.category, NEW.quantity, COALESCE(current_qty, 0);
      END IF;
    ELSE
      -- Central stock path (identical to the previous non-negative guard logic).
      INSERT INTO public.stocks (category, quantity)
        VALUES (NEW.category, 0)
        ON CONFLICT (category) DO NOTHING;
      UPDATE public.stocks
        SET quantity = quantity - NEW.quantity
        WHERE category = NEW.category AND quantity >= NEW.quantity;
      IF NOT FOUND THEN
        SELECT quantity INTO current_qty FROM public.stocks WHERE category = NEW.category;
        RAISE EXCEPTION 'STOCK_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
          NEW.category, NEW.quantity, COALESCE(current_qty, 0);
      END IF;
    END IF;

  -- ── DELETE: deleted sale releases stock ─────────────────────────────────────
  ELSIF TG_OP = 'DELETE' THEN
    use_commercial := (
      OLD.created_by IS NOT NULL AND
      EXISTS (
        SELECT 1 FROM public.stock_commercial
        WHERE user_id = OLD.created_by AND category = OLD.category
      )
    );
    IF use_commercial THEN
      INSERT INTO public.stock_commercial (user_id, category, quantity)
        VALUES (OLD.created_by, OLD.category, OLD.quantity)
        ON CONFLICT (user_id, category)
        DO UPDATE SET quantity = public.stock_commercial.quantity + OLD.quantity;
    ELSE
      INSERT INTO public.stocks (category, quantity)
        VALUES (OLD.category, OLD.quantity)
        ON CONFLICT (category)
        DO UPDATE SET quantity = public.stocks.quantity + OLD.quantity;
    END IF;

  -- ── UPDATE: undo old effect, apply new effect ────────────────────────────────
  ELSIF TG_OP = 'UPDATE' THEN
    -- Only act when category, quantity, or created_by actually changed.
    IF OLD.category IS DISTINCT FROM NEW.category
       OR OLD.quantity IS DISTINCT FROM NEW.quantity
       OR OLD.created_by IS DISTINCT FROM NEW.created_by THEN

      -- 1. Restore old quantity to its original stock pool.
      use_commercial := (
        OLD.created_by IS NOT NULL AND
        EXISTS (
          SELECT 1 FROM public.stock_commercial
          WHERE user_id = OLD.created_by AND category = OLD.category
        )
      );
      IF use_commercial THEN
        INSERT INTO public.stock_commercial (user_id, category, quantity)
          VALUES (OLD.created_by, OLD.category, OLD.quantity)
          ON CONFLICT (user_id, category)
          DO UPDATE SET quantity = public.stock_commercial.quantity + OLD.quantity;
      ELSE
        INSERT INTO public.stocks (category, quantity)
          VALUES (OLD.category, OLD.quantity)
          ON CONFLICT (category)
          DO UPDATE SET quantity = public.stocks.quantity + OLD.quantity;
      END IF;

      -- 2. Deduct new quantity from the appropriate stock pool.
      use_commercial := (
        NEW.created_by IS NOT NULL AND
        EXISTS (
          SELECT 1 FROM public.stock_commercial
          WHERE user_id = NEW.created_by AND category = NEW.category
        )
      );
      IF use_commercial THEN
        UPDATE public.stock_commercial
          SET quantity = quantity - NEW.quantity
          WHERE user_id = NEW.created_by
            AND category = NEW.category
            AND quantity >= NEW.quantity;
        IF NOT FOUND THEN
          SELECT quantity INTO current_qty
            FROM public.stock_commercial
            WHERE user_id = NEW.created_by AND category = NEW.category;
          RAISE EXCEPTION 'STOCK_COMMERCIAL_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
            NEW.category, NEW.quantity, COALESCE(current_qty, 0);
        END IF;
      ELSE
        INSERT INTO public.stocks (category, quantity)
          VALUES (NEW.category, 0)
          ON CONFLICT (category) DO NOTHING;
        UPDATE public.stocks
          SET quantity = quantity - NEW.quantity
          WHERE category = NEW.category AND quantity >= NEW.quantity;
        IF NOT FOUND THEN
          SELECT quantity INTO current_qty FROM public.stocks WHERE category = NEW.category;
          RAISE EXCEPTION 'STOCK_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
            NEW.category, NEW.quantity, COALESCE(current_qty, 0);
        END IF;
      END IF;

    END IF; -- category/quantity/created_by changed
  END IF;   -- TG_OP

  RETURN NULL;
END;
$$;

-- Re-create the trigger so any signature change takes effect.
DROP TRIGGER IF EXISTS trg_sales_adjust_stock ON public.sales;

CREATE TRIGGER trg_sales_adjust_stock
  AFTER INSERT OR UPDATE OR DELETE
  ON public.sales
  FOR EACH ROW
  EXECUTE FUNCTION public.adjust_stock_on_sale_change();
