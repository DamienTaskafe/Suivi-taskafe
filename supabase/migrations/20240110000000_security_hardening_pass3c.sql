-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Security hardening pass 3C — sales-driven stock adjustments via DB trigger
-- ─────────────────────────────────────────────────────────────────────────────
-- Scope: Move stock adjustments caused by sales mutations from client-side
-- stocks upserts to an atomic database trigger on public.sales.
--
-- What this migration does
-- ─────────────────────────
-- Creates a trigger function adjust_stock_on_sale_change() and a trigger
-- trg_sales_adjust_stock that fires AFTER INSERT, UPDATE, or DELETE on
-- public.sales for each affected row.
--
-- Delta logic:
--   INSERT sale  → decrement stock for NEW.category by NEW.quantity
--   DELETE sale  → increment stock for OLD.category by OLD.quantity
--   UPDATE sale  → undo old effect (increment OLD.category by OLD.quantity)
--                  then apply new effect (decrement NEW.category by NEW.quantity)
--                  Only fires when category or quantity actually changes;
--                  updates that only change paid/client_name/etc. are no-ops.
--
-- The trigger uses INSERT … ON CONFLICT DO UPDATE so that a missing stock row
-- is seeded at 0 before the delta is applied (safe for any category).
--
-- The function is marked SECURITY DEFINER so it runs with the privileges of
-- the function owner (postgres / supabase_admin), bypassing RLS on the stocks
-- table.  This ensures the adjustment still works after stocks UPDATE RLS is
-- tightened in a later pass.
--
-- What is intentionally deferred
-- ─────────────────────────────────────────────
-- • stocks UPDATE RLS tightening: deferred until a future pass (3D).
--   Employees still have direct stock UPDATE access for addToStock / setStock
--   flows; removing that requires a separate client-side change first.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. Trigger function ──────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.adjust_stock_on_sale_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    -- A new sale consumes stock: decrement the category quantity.
    INSERT INTO public.stocks (category, quantity)
      VALUES (NEW.category, -NEW.quantity)
    ON CONFLICT (category)
      DO UPDATE SET quantity = public.stocks.quantity - NEW.quantity;

  ELSIF TG_OP = 'DELETE' THEN
    -- A deleted sale releases stock: increment the category quantity.
    INSERT INTO public.stocks (category, quantity)
      VALUES (OLD.category, OLD.quantity)
    ON CONFLICT (category)
      DO UPDATE SET quantity = public.stocks.quantity + OLD.quantity;

  ELSIF TG_OP = 'UPDATE' THEN
    -- Only adjust when category or quantity actually changed; skip pure
    -- metadata updates (paid toggle, client rename, etc.) to avoid phantom
    -- adjustments.
    IF OLD.category IS DISTINCT FROM NEW.category
       OR OLD.quantity IS DISTINCT FROM NEW.quantity THEN

      -- Undo old sale's stock consumption.
      INSERT INTO public.stocks (category, quantity)
        VALUES (OLD.category, OLD.quantity)
      ON CONFLICT (category)
        DO UPDATE SET quantity = public.stocks.quantity + OLD.quantity;

      -- Apply new sale's stock consumption.
      INSERT INTO public.stocks (category, quantity)
        VALUES (NEW.category, -NEW.quantity)
      ON CONFLICT (category)
        DO UPDATE SET quantity = public.stocks.quantity - NEW.quantity;

    END IF;
  END IF;

  RETURN NULL; -- return value is ignored for AFTER row-level triggers
END;
$$;


-- ── 2. Trigger ───────────────────────────────────────────────────────────────

-- Drop any previous incarnation so this migration is idempotent.
DROP TRIGGER IF EXISTS trg_sales_adjust_stock ON public.sales;

CREATE TRIGGER trg_sales_adjust_stock
  AFTER INSERT OR UPDATE OR DELETE
  ON public.sales
  FOR EACH ROW
  EXECUTE FUNCTION public.adjust_stock_on_sale_change();
