-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Robust structured errors in adjust_stock_on_sale_change()
-- ─────────────────────────────────────────────────────────────────────────────
-- Why this migration exists
-- ─────────────────────────
-- The previous trigger version (from stock_commercial migration) already raises
-- STOCK_INSUFFISANT / STOCK_COMMERCIAL_INSUFFISANT with embedded qty values.
-- However, if a Supabase environment was initialised from an older snapshot
-- (e.g. stock_nonneg_guard only, without stock_commercial) the active trigger
-- may still raise raw PostgreSQL check-constraint errors ("stocks_quantity_check")
-- that the frontend cannot translate into a coherent French message.
--
-- This migration is an idempotent safety net that unconditionally re-installs
-- the latest version of adjust_stock_on_sale_change() so every environment
-- produces structured STOCK_INSUFFISANT / STOCK_COMMERCIAL_INSUFFISANT messages
-- with catégorie=, demandé=, and disponible= embedded in the error text.
-- This allows the frontend getFriendlyErrorMessage() to extract accurate values
-- from the DB error rather than relying on potentially-stale local state.
--
-- Changes vs. previous version
-- ─────────────────────────────
-- • No logic change — routing and guard semantics are identical.
-- • Adds inline comments explaining the structured-error contract so future
--   developers understand why the RAISE EXCEPTION format must be preserved.
-- • Idempotent: CREATE OR REPLACE + DROP/CREATE trigger — safe to re-run.
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
    -- Route to commercial stock when the selling user has a stock_commercial row
    -- for this category (row presence opts the user into commercial-stock mode;
    -- absence falls back to the central pool — backward-compatible).
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
        -- Structured error: frontend parses catégorie=, demandé=, disponible=
        SELECT quantity INTO current_qty
          FROM public.stock_commercial
          WHERE user_id = NEW.created_by AND category = NEW.category;
        RAISE EXCEPTION 'STOCK_COMMERCIAL_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
          NEW.category, NEW.quantity, COALESCE(current_qty, 0);
      END IF;

    ELSE
      -- Central stock path.
      -- Seed the row at 0 if absent so the UPDATE has a row to lock.
      INSERT INTO public.stocks (category, quantity)
        VALUES (NEW.category, 0)
        ON CONFLICT (category) DO NOTHING;

      UPDATE public.stocks
        SET quantity = quantity - NEW.quantity
        WHERE category = NEW.category AND quantity >= NEW.quantity;

      IF NOT FOUND THEN
        -- Structured error: frontend parses catégorie=, demandé=, disponible=
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

-- Re-create the trigger so any signature change takes effect (idempotent).
DROP TRIGGER IF EXISTS trg_sales_adjust_stock ON public.sales;

CREATE TRIGGER trg_sales_adjust_stock
  AFTER INSERT OR UPDATE OR DELETE
  ON public.sales
  FOR EACH ROW
  EXECUTE FUNCTION public.adjust_stock_on_sale_change();
