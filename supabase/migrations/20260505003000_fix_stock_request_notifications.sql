-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Fix stock request notifications
-- Idempotent — safe to run multiple times.
--
-- Changes:
--   1. create_stock_request  — also sends a confirmation notification to the
--      employee so they can track their request in the bell/history.
--   2. cancel_stock_request  — sends notifications to the relevant parties:
--      • Employee cancels → admins/managers are notified.
--      • Admin/manager cancels → the employee is notified.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── 1. create_stock_request() — add employee confirmation ────────────────────

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
      '📦 Nouvelle demande de stock',
      v_msg,
      jsonb_build_object('request_id', v_id, 'employee_id', auth.uid(), 'items', p_items),
      auth.uid()
    );
  END LOOP;

  -- Confirmation notification for the employee themselves
  INSERT INTO public.notifications (user_id, type, title, message, payload, created_by)
  VALUES (
    auth.uid(),
    'stock_request',
    '📤 Demande de stock envoyée',
    E'Votre demande a été envoyée :\n' || v_lines,
    jsonb_build_object('request_id', v_id, 'items', p_items),
    auth.uid()
  );

  RETURN v_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.create_stock_request(jsonb, text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.create_stock_request(jsonb, text) TO authenticated;

-- ── 2. cancel_stock_request() — add notifications ────────────────────────────

CREATE OR REPLACE FUNCTION public.cancel_stock_request(
  p_request_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_req       public.stock_requests%ROWTYPE;
  v_admin     RECORD;
  v_emp_name  text;
  v_is_admin  boolean;
BEGIN
  SELECT * INTO v_req FROM public.stock_requests WHERE id = p_request_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'DEMANDE_INTROUVABLE';
  END IF;

  -- Determine if the caller is an admin/manager
  v_is_admin := EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND role IN ('admin', 'manager')
  );

  -- Employee can only cancel their own pending/preparing requests
  IF v_req.employee_id = auth.uid() THEN
    IF v_req.status NOT IN ('pending', 'preparing') THEN
      RAISE EXCEPTION 'ANNULATION_IMPOSSIBLE: statut actuel est %', v_req.status;
    END IF;
  ELSIF NOT v_is_admin THEN
    RAISE EXCEPTION 'PERMISSION_DENIED';
  END IF;

  UPDATE public.stock_requests
  SET status = 'cancelled', updated_at = now()
  WHERE id = p_request_id;

  -- Notifications
  IF NOT v_is_admin THEN
    -- Employee cancelled their own request: notify all admins/managers
    SELECT COALESCE(full_name, email, auth.uid()::text)
    INTO v_emp_name
    FROM public.profiles WHERE id = auth.uid();

    FOR v_admin IN
      SELECT id FROM public.profiles WHERE role IN ('admin', 'manager')
    LOOP
      INSERT INTO public.notifications (user_id, type, title, message, payload, created_by)
      VALUES (
        v_admin.id,
        'stock_request_status',
        '🚫 Demande annulée',
        v_emp_name || ' a annulé sa demande de stock.',
        jsonb_build_object('request_id', p_request_id, 'status', 'cancelled'),
        auth.uid()
      );
    END LOOP;

    -- Also inform the employee (confirmation of their own cancellation)
    INSERT INTO public.notifications (user_id, type, title, message, payload, created_by)
    VALUES (
      v_req.employee_id,
      'stock_request_status',
      '🚫 Demande annulée',
      'Votre demande de stock a été annulée.',
      jsonb_build_object('request_id', p_request_id, 'status', 'cancelled'),
      auth.uid()
    );
  ELSE
    -- Admin/manager cancelled: notify the employee
    INSERT INTO public.notifications (user_id, type, title, message, payload, created_by)
    VALUES (
      v_req.employee_id,
      'stock_request_status',
      '🚫 Demande annulée',
      'Votre demande de stock a été annulée.',
      jsonb_build_object('request_id', p_request_id, 'status', 'cancelled'),
      auth.uid()
    );
  END IF;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.cancel_stock_request(uuid) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.cancel_stock_request(uuid) TO authenticated;

-- ── 3. Ensure notifications table INSERT is also allowed to service-role ──────
-- SECURITY DEFINER functions run as the function owner (postgres/service role)
-- which already bypasses RLS.  This comment is kept as documentation.
-- No additional grants are required.
