-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Align sales stock trigger with role-based stock routing
-- ─────────────────────────────────────────────────────────────────────────────
-- Problem fixed
-- ─────────────
-- The frontend/business rule is:
--   • admin / manager sales consume central stock (public.stocks)
--   • employee sales consume stock_commercial only when a row exists for
--     (employee, category); otherwise they fall back to central stock
--
-- The previous trigger used stock_commercial whenever a row existed for
-- NEW.created_by + category, regardless of the user's role. If an admin/manager
-- had a leftover stock_commercial row, the app could show central ORO = 60 and
-- requested = 10 while the DB trigger tried to consume the admin's commercial
-- row instead, producing a false "stock insuffisant" error.
--
-- This migration re-installs adjust_stock_on_sale_change() so DB routing matches
-- the app and the business model exactly.
-- ─────────────────────────────────────────────────────────────────────────────

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
    -- Commercial stock is used only for non-admin/non-manager users that have a
    -- stock_commercial row for this category. Admins/managers always use central
    -- stock, even if a legacy stock_commercial row exists for their user id.
    use_commercial := (
      NEW.created_by IS NOT NULL
      AND NOT EXISTS (
        SELECT 1
        FROM public.profiles p
        WHERE p.id = NEW.created_by
          AND p.role IN ('admin', 'manager')
      )
      AND EXISTS (
        SELECT 1
        FROM public.stock_commercial sc
        WHERE sc.user_id = NEW.created_by
          AND sc.category = NEW.category
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
          WHERE user_id = NEW.created_by
            AND category = NEW.category;

        RAISE EXCEPTION 'STOCK_COMMERCIAL_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
          NEW.category, NEW.quantity, COALESCE(current_qty, 0);
      END IF;
    ELSE
      INSERT INTO public.stocks (category, quantity)
        VALUES (NEW.category, 0)
        ON CONFLICT (category) DO NOTHING;

      UPDATE public.stocks
        SET quantity = quantity - NEW.quantity
        WHERE category = NEW.category
          AND quantity >= NEW.quantity;

      IF NOT FOUND THEN
        SELECT quantity INTO current_qty
          FROM public.stocks
          WHERE category = NEW.category;

        RAISE EXCEPTION 'STOCK_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
          NEW.category, NEW.quantity, COALESCE(current_qty, 0);
      END IF;
    END IF;

  -- ── DELETE: deleted sale releases stock ─────────────────────────────────────
  ELSIF TG_OP = 'DELETE' THEN
    use_commercial := (
      OLD.created_by IS NOT NULL
      AND NOT EXISTS (
        SELECT 1
        FROM public.profiles p
        WHERE p.id = OLD.created_by
          AND p.role IN ('admin', 'manager')
      )
      AND EXISTS (
        SELECT 1
        FROM public.stock_commercial sc
        WHERE sc.user_id = OLD.created_by
          AND sc.category = OLD.category
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

  -- ── UPDATE: undo old effect, apply new effect ───────────────────────────────
  ELSIF TG_OP = 'UPDATE' THEN
    IF OLD.category IS DISTINCT FROM NEW.category
       OR OLD.quantity IS DISTINCT FROM NEW.quantity
       OR OLD.created_by IS DISTINCT FROM NEW.created_by THEN

      -- 1. Restore old quantity to the pool dictated by the old sale owner.
      use_commercial := (
        OLD.created_by IS NOT NULL
        AND NOT EXISTS (
          SELECT 1
          FROM public.profiles p
          WHERE p.id = OLD.created_by
            AND p.role IN ('admin', 'manager')
        )
        AND EXISTS (
          SELECT 1
          FROM public.stock_commercial sc
          WHERE sc.user_id = OLD.created_by
            AND sc.category = OLD.category
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

      -- 2. Deduct new quantity from the pool dictated by the new sale owner.
      use_commercial := (
        NEW.created_by IS NOT NULL
        AND NOT EXISTS (
          SELECT 1
          FROM public.profiles p
          WHERE p.id = NEW.created_by
            AND p.role IN ('admin', 'manager')
        )
        AND EXISTS (
          SELECT 1
          FROM public.stock_commercial sc
          WHERE sc.user_id = NEW.created_by
            AND sc.category = NEW.category
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
            WHERE user_id = NEW.created_by
              AND category = NEW.category;

          RAISE EXCEPTION 'STOCK_COMMERCIAL_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
            NEW.category, NEW.quantity, COALESCE(current_qty, 0);
        END IF;
      ELSE
        INSERT INTO public.stocks (category, quantity)
          VALUES (NEW.category, 0)
          ON CONFLICT (category) DO NOTHING;

        UPDATE public.stocks
          SET quantity = quantity - NEW.quantity
          WHERE category = NEW.category
            AND quantity >= NEW.quantity;

        IF NOT FOUND THEN
          SELECT quantity INTO current_qty
            FROM public.stocks
            WHERE category = NEW.category;

          RAISE EXCEPTION 'STOCK_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
            NEW.category, NEW.quantity, COALESCE(current_qty, 0);
        END IF;
      END IF;
    END IF;
  END IF;

  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_sales_adjust_stock ON public.sales;

CREATE TRIGGER trg_sales_adjust_stock
  AFTER INSERT OR UPDATE OR DELETE
  ON public.sales
  FOR EACH ROW
  EXECUTE FUNCTION public.adjust_stock_on_sale_change();
