-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: stock_requests + stock_losses tables, RLS, and RPCs
-- Idempotent — safe to run multiple times.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── 1. stock_requests table ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.stock_requests (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  employee_id uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  items       jsonb       NOT NULL DEFAULT '[]'::jsonb,
  notes       text        NULL,
  status      text        NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','preparing','ready_pickup','fulfilled','rejected','cancelled')),
  admin_notes text        NULL,
  handled_by  uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  handled_at  timestamptz NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.stock_requests ENABLE ROW LEVEL SECURITY;

-- ── 2. stock_losses table ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.stock_losses (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  employee_id uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  category    text        NOT NULL,
  quantity    numeric     NOT NULL CHECK (quantity > 0),
  reason      text        NOT NULL,
  notes       text        NULL,
  created_by  uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.stock_losses ENABLE ROW LEVEL SECURITY;

-- ── 3. RLS policies ───────────────────────────────────────────────────────────

-- stock_requests: employees see their own; admins/managers see all
DROP POLICY IF EXISTS "stock_requests_select" ON public.stock_requests;
CREATE POLICY "stock_requests_select"
  ON public.stock_requests FOR SELECT
  TO authenticated
  USING (
    employee_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

-- Employees can create their own requests
DROP POLICY IF EXISTS "stock_requests_insert_employee" ON public.stock_requests;
CREATE POLICY "stock_requests_insert_employee"
  ON public.stock_requests FOR INSERT
  TO authenticated
  WITH CHECK (employee_id = auth.uid());

-- Only admin/manager can update (change status, notes, etc.)
DROP POLICY IF EXISTS "stock_requests_update_admin" ON public.stock_requests;
CREATE POLICY "stock_requests_update_admin"
  ON public.stock_requests FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
    OR (
      -- Employee can cancel their own pending/preparing request
      employee_id = auth.uid()
      AND status IN ('pending', 'preparing')
    )
  )
  WITH CHECK (true);

-- stock_losses: only admin/manager can insert/read
DROP POLICY IF EXISTS "stock_losses_select" ON public.stock_losses;
CREATE POLICY "stock_losses_select"
  ON public.stock_losses FOR SELECT
  TO authenticated
  USING (
    employee_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

DROP POLICY IF EXISTS "stock_losses_insert_admin" ON public.stock_losses;
CREATE POLICY "stock_losses_insert_admin"
  ON public.stock_losses FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

GRANT SELECT, INSERT, UPDATE ON public.stock_requests TO authenticated;
GRANT SELECT, INSERT ON public.stock_losses TO authenticated;

-- ── 4. create_stock_request() ─────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.create_stock_request(
  p_items jsonb,
  p_notes text DEFAULT NULL
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_id       uuid;
  v_admin    RECORD;
  v_emp_name text;
  v_msg      text;
  v_item     jsonb;
  v_lines    text := '';
BEGIN
  -- Basic validation: items must be a non-empty array
  IF jsonb_typeof(p_items) <> 'array' OR jsonb_array_length(p_items) = 0 THEN
    RAISE EXCEPTION 'ITEMS_INVALIDES: au moins un produit requis';
  END IF;

  INSERT INTO public.stock_requests (employee_id, items, notes)
  VALUES (auth.uid(), p_items, p_notes)
  RETURNING id INTO v_id;

  -- Build employee display name
  SELECT COALESCE(full_name, email, auth.uid()::text)
  INTO v_emp_name
  FROM public.profiles WHERE id = auth.uid();

  -- Build message lines
  FOR v_item IN SELECT jsonb_array_elements(p_items) LOOP
    v_lines := v_lines || E'- ' || (v_item->>'category') || ' : ' || (v_item->>'quantity') || E'\n';
  END LOOP;
  v_msg := v_emp_name || E' demande :\n' || v_lines;

  -- Notify all admins and managers
  FOR v_admin IN
    SELECT id FROM public.profiles WHERE role IN ('admin', 'manager')
  LOOP
    INSERT INTO public.notifications (user_id, type, title, message, payload, created_by)
    VALUES (
      v_admin.id,
      'stock_request',
      '📦 Demande de stock',
      v_msg,
      jsonb_build_object('request_id', v_id, 'employee_id', auth.uid(), 'items', p_items),
      auth.uid()
    );
  END LOOP;

  RETURN v_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.create_stock_request(jsonb, text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.create_stock_request(jsonb, text) TO authenticated;

-- ── 5. cancel_stock_request() ─────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.cancel_stock_request(
  p_request_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_req public.stock_requests%ROWTYPE;
BEGIN
  SELECT * INTO v_req FROM public.stock_requests WHERE id = p_request_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'DEMANDE_INTROUVABLE';
  END IF;

  -- Employee can only cancel their own pending/preparing requests
  IF v_req.employee_id = auth.uid() THEN
    IF v_req.status NOT IN ('pending', 'preparing') THEN
      RAISE EXCEPTION 'ANNULATION_IMPOSSIBLE: statut actuel est %', v_req.status;
    END IF;
  ELSIF NOT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND role IN ('admin', 'manager')
  ) THEN
    RAISE EXCEPTION 'PERMISSION_DENIED';
  END IF;

  UPDATE public.stock_requests
  SET status = 'cancelled', updated_at = now()
  WHERE id = p_request_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.cancel_stock_request(uuid) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.cancel_stock_request(uuid) TO authenticated;

-- ── 6. update_stock_request_status() ─────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.update_stock_request_status(
  p_request_id  uuid,
  p_status      text,
  p_admin_notes text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_req    public.stock_requests%ROWTYPE;
  v_title  text;
  v_msg    text;
  v_lines  text := '';
  v_item   jsonb;
BEGIN
  -- Admin/manager only
  IF NOT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND role IN ('admin', 'manager')
  ) THEN
    RAISE EXCEPTION 'PERMISSION_DENIED';
  END IF;

  IF p_status NOT IN ('pending','preparing','ready_pickup','fulfilled','rejected','cancelled') THEN
    RAISE EXCEPTION 'STATUT_INVALIDE: %', p_status;
  END IF;

  UPDATE public.stock_requests
  SET
    status      = p_status,
    admin_notes = COALESCE(p_admin_notes, admin_notes),
    handled_by  = auth.uid(),
    handled_at  = now(),
    updated_at  = now()
  WHERE id = p_request_id
  RETURNING * INTO v_req;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'DEMANDE_INTROUVABLE';
  END IF;

  -- Build item lines for ready_pickup notification
  IF p_status = 'ready_pickup' THEN
    FOR v_item IN SELECT jsonb_array_elements(v_req.items) LOOP
      v_lines := v_lines || E'- ' || (v_item->>'category') || ' : ' || (v_item->>'quantity') || E'\n';
    END LOOP;
  END IF;

  -- Notify the employee based on new status
  IF p_status = 'preparing' THEN
    v_title := '📦 Demande en préparation';
    v_msg   := 'Votre demande est en cours de préparation.';
  ELSIF p_status = 'ready_pickup' THEN
    v_title := '✅ Stock prêt à récupérer';
    v_msg   := E'Vous pouvez passer récupérer :\n' || v_lines;
  ELSIF p_status = 'rejected' THEN
    v_title := '❌ Demande refusée';
    v_msg   := 'Votre demande a été refusée.' || COALESCE(' ' || p_admin_notes, '');
  ELSIF p_status = 'cancelled' THEN
    v_title := '🚫 Demande annulée';
    v_msg   := 'Votre demande a été annulée.';
  ELSE
    -- No notification for 'pending'
    RETURN;
  END IF;

  INSERT INTO public.notifications (user_id, type, title, message, payload, created_by)
  VALUES (
    v_req.employee_id,
    'stock_request_status',
    v_title,
    v_msg,
    jsonb_build_object('request_id', p_request_id, 'status', p_status),
    auth.uid()
  );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.update_stock_request_status(uuid, text, text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.update_stock_request_status(uuid, text, text) TO authenticated;

-- ── 7. fulfill_stock_request() ────────────────────────────────────────────────
-- Atomically transfers stock and marks request fulfilled.

CREATE OR REPLACE FUNCTION public.fulfill_stock_request(
  p_request_id  uuid,
  p_admin_notes text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_req       public.stock_requests%ROWTYPE;
  v_item      jsonb;
  v_category  text;
  v_quantity  numeric;
  v_central   numeric;
BEGIN
  -- Admin/manager only
  IF NOT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND role IN ('admin', 'manager')
  ) THEN
    RAISE EXCEPTION 'PERMISSION_DENIED';
  END IF;

  SELECT * INTO v_req FROM public.stock_requests WHERE id = p_request_id FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'DEMANDE_INTROUVABLE';
  END IF;

  IF v_req.status = 'fulfilled' THEN
    RAISE EXCEPTION 'DEJA_FULFILLED';
  END IF;

  IF v_req.status IN ('rejected', 'cancelled') THEN
    RAISE EXCEPTION 'DEMANDE_TERMINEE: statut=%', v_req.status;
  END IF;

  -- Pre-check all items have sufficient central stock
  FOR v_item IN SELECT jsonb_array_elements(v_req.items)
  LOOP
    v_category := v_item->>'category';
    v_quantity := (v_item->>'quantity')::numeric;

    IF v_category IS NULL OR v_quantity IS NULL OR v_quantity <= 0 THEN
      RAISE EXCEPTION 'ITEM_INVALIDE: catégorie=%, quantité=%', v_category, v_quantity;
    END IF;

    SELECT COALESCE(quantity, 0) INTO v_central
    FROM public.stocks WHERE category = v_category;

    IF COALESCE(v_central, 0) < v_quantity THEN
      RAISE EXCEPTION 'STOCK_CENTRAL_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
        v_category, v_quantity, COALESCE(v_central, 0);
    END IF;
  END LOOP;

  -- Execute transfers for each item
  FOR v_item IN SELECT jsonb_array_elements(v_req.items)
  LOOP
    v_category := v_item->>'category';
    v_quantity := (v_item->>'quantity')::numeric;

    -- Deduct from central stock
    UPDATE public.stocks
    SET quantity = quantity - v_quantity
    WHERE category = v_category;

    -- Add to employee commercial stock
    INSERT INTO public.stock_commercial (user_id, category, quantity)
    VALUES (v_req.employee_id, v_category, v_quantity)
    ON CONFLICT (user_id, category)
    DO UPDATE SET quantity = public.stock_commercial.quantity + v_quantity;

    -- Audit trail
    INSERT INTO public.stock_movements (movement_type, employee_id, category, quantity, created_by)
    VALUES ('central_to_commercial', v_req.employee_id, v_category, v_quantity, auth.uid());
  END LOOP;

  -- Mark request fulfilled
  UPDATE public.stock_requests
  SET
    status      = 'fulfilled',
    admin_notes = COALESCE(p_admin_notes, admin_notes),
    handled_by  = auth.uid(),
    handled_at  = now(),
    updated_at  = now()
  WHERE id = p_request_id;

  -- Notify the employee
  INSERT INTO public.notifications (user_id, type, title, message, payload, created_by)
  VALUES (
    v_req.employee_id,
    'stock_request_status',
    '✅ Stock remis',
    'Votre stock a été remis et transféré dans votre stock voiture.',
    jsonb_build_object('request_id', p_request_id, 'status', 'fulfilled'),
    auth.uid()
  );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.fulfill_stock_request(uuid, text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.fulfill_stock_request(uuid, text) TO authenticated;

-- ── 8. return_all_commercial_stock() ─────────────────────────────────────────
-- Returns all commercial stock of an employee to central stock atomically.

CREATE OR REPLACE FUNCTION public.return_all_commercial_stock(
  p_employee_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_row    public.stock_commercial%ROWTYPE;
  v_result jsonb := '[]'::jsonb;
BEGIN
  -- Admin/manager only
  IF NOT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND role IN ('admin', 'manager')
  ) THEN
    RAISE EXCEPTION 'PERMISSION_DENIED';
  END IF;

  FOR v_row IN
    SELECT * FROM public.stock_commercial
    WHERE user_id = p_employee_id AND quantity > 0
    FOR UPDATE
  LOOP
    -- Add back to central
    INSERT INTO public.stocks (category, quantity)
    VALUES (v_row.category, v_row.quantity)
    ON CONFLICT (category)
    DO UPDATE SET quantity = public.stocks.quantity + v_row.quantity;

    -- Audit trail
    INSERT INTO public.stock_movements (movement_type, employee_id, category, quantity, created_by)
    VALUES ('commercial_to_central', p_employee_id, v_row.category, v_row.quantity, auth.uid());

    -- Append to result
    v_result := v_result || jsonb_build_array(
      jsonb_build_object('category', v_row.category, 'quantity', v_row.quantity)
    );

    -- Zero out commercial stock
    UPDATE public.stock_commercial
    SET quantity = 0
    WHERE user_id = p_employee_id AND category = v_row.category;
  END LOOP;

  RETURN v_result;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.return_all_commercial_stock(uuid) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.return_all_commercial_stock(uuid) TO authenticated;

-- ── 9. declare_commercial_stock_loss() ───────────────────────────────────────

CREATE OR REPLACE FUNCTION public.declare_commercial_stock_loss(
  p_employee_id uuid,
  p_category    text,
  p_quantity    numeric,
  p_reason      text,
  p_notes       text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_commercial_qty numeric;
BEGIN
  -- Admin/manager only
  IF NOT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND role IN ('admin', 'manager')
  ) THEN
    RAISE EXCEPTION 'PERMISSION_DENIED';
  END IF;

  IF p_quantity <= 0 THEN
    RAISE EXCEPTION 'QUANTITE_INVALIDE: la quantité doit être positive (reçu: %)', p_quantity;
  END IF;

  -- Check commercial stock sufficiency
  SELECT COALESCE(quantity, 0) INTO v_commercial_qty
  FROM public.stock_commercial
  WHERE user_id = p_employee_id AND category = p_category;

  IF COALESCE(v_commercial_qty, 0) < p_quantity THEN
    RAISE EXCEPTION 'STOCK_COMMERCIAL_INSUFFISANT: catégorie=%, demandé=%, disponible=%',
      p_category, p_quantity, COALESCE(v_commercial_qty, 0);
  END IF;

  -- Deduct from commercial stock (do NOT touch central stock)
  UPDATE public.stock_commercial
  SET quantity = quantity - p_quantity
  WHERE user_id = p_employee_id AND category = p_category;

  -- Record loss
  INSERT INTO public.stock_losses (employee_id, category, quantity, reason, notes, created_by)
  VALUES (p_employee_id, p_category, p_quantity, p_reason, p_notes, auth.uid());

  -- Audit trail in stock_movements
  INSERT INTO public.stock_movements (movement_type, employee_id, category, quantity, notes, created_by)
  VALUES ('commercial_loss', p_employee_id, p_category, p_quantity, p_reason, auth.uid());
END;
$$;

REVOKE EXECUTE ON FUNCTION public.declare_commercial_stock_loss(uuid, text, numeric, text, text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.declare_commercial_stock_loss(uuid, text, numeric, text, text) TO authenticated;
