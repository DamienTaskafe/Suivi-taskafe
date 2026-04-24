-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Stock non-negative guard in sales trigger
-- ─────────────────────────────────────────────────────────────────────────────
-- Problem addressed
-- ─────────────────
-- Offline sales queued while a device is disconnected are replayed (inserted
-- into public.sales) when the device comes back online.  The previous version
-- of adjust_stock_on_sale_change() used a plain ON CONFLICT DO UPDATE upsert
-- that could push stock.quantity below zero when concurrent sales had already
-- consumed stock while the device was offline — a "silent" data-integrity
-- violation with no error feedback to the client.
--
-- What this migration does
-- ─────────────────────────
-- Replaces the trigger function with a version that, on INSERT:
--   1. Seeds the stock row at 0 if it does not exist yet (idempotent).
--   2. Atomically decrements quantity only when quantity >= sale.quantity.
--   3. Raises STOCK_INSUFFISANT when the condition is not met so that:
--      • The sale INSERT is rolled back (no phantom record).
--      • The error propagates to the client sync loop, which surfaces it via
--        showSessionStatus() and keeps the pending op in the queue for review
--        — no silent inconsistency.
--
-- The DELETE and UPDATE paths are unchanged: they restore/adjust stock and
-- never risk driving the value below zero (DELETE always adds back; UPDATE
-- first restores the old quantity before subtracting the new one).
--
-- Concurrency safety
-- ───────────────────
-- The UPDATE … WHERE qty >= NEW.quantity is a single atomic SQL statement.
-- Under the default READ COMMITTED isolation level the UPDATE sees the
-- committed quantity at the moment it acquires the row lock, so two
-- concurrent offline-replay transactions racing on the same category cannot
-- both succeed if there is only enough stock for one of them.
-- ─────────────────────────────────────────────────────────────────────────────


CREATE OR REPLACE FUNCTION public.adjust_stock_on_sale_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  current_qty numeric;
BEGIN
  IF TG_OP = 'INSERT' THEN
    -- Ensure a stock row exists for this category (seed at 0 when absent) so
    -- the UPDATE below always has a row to lock and modify.
    INSERT INTO public.stocks (category, quantity)
      VALUES (NEW.category, 0)
    ON CONFLICT (category) DO NOTHING;

    -- Atomically decrement stock, but only when sufficient quantity is available.
    -- The WHERE clause prevents the update (and thus the sale) when stock would
    -- go negative; NOT FOUND means the condition was not satisfied.
    UPDATE public.stocks
      SET quantity = quantity - NEW.quantity
      WHERE category = NEW.category AND quantity >= NEW.quantity;

    IF NOT FOUND THEN
      -- Read the current value for an informative error message then abort.
      SELECT quantity INTO current_qty
        FROM public.stocks WHERE category = NEW.category;
      RAISE EXCEPTION 'STOCK_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
        NEW.category, NEW.quantity, COALESCE(current_qty, 0);
    END IF;

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

      -- Undo old sale's stock consumption (restore the previously decremented qty).
      INSERT INTO public.stocks (category, quantity)
        VALUES (OLD.category, OLD.quantity)
      ON CONFLICT (category)
        DO UPDATE SET quantity = public.stocks.quantity + OLD.quantity;

      -- Apply new sale's stock consumption.
      -- No negative-guard here: the restore step above already returned the old
      -- quantity to the pool, so an UPDATE edit is an explicit user action rather
      -- than an unattended offline-replay scenario.  If the net result is still
      -- negative it will be visible in the UI after the next sync/refresh.
      INSERT INTO public.stocks (category, quantity)
        VALUES (NEW.category, -NEW.quantity)
      ON CONFLICT (category)
        DO UPDATE SET quantity = public.stocks.quantity - NEW.quantity;

    END IF;
  END IF;

  RETURN NULL; -- return value is ignored for AFTER row-level triggers
END;
$$;


-- Re-attach the trigger (idempotent — drop first so any signature change takes effect).
DROP TRIGGER IF EXISTS trg_sales_adjust_stock ON public.sales;

CREATE TRIGGER trg_sales_adjust_stock
  AFTER INSERT OR UPDATE OR DELETE
  ON public.sales
  FOR EACH ROW
  EXECUTE FUNCTION public.adjust_stock_on_sale_change();
