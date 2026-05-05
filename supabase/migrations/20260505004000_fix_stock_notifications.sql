-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: fix stock request notification gaps
-- Idempotent — safe to run multiple times.
--
-- Changes vs 20260505002000_stock_requests_losses.sql:
--   1. create_stock_request()   → also inserts an employee self-confirmation row.
--   2. cancel_stock_request()   → employee-cancel: notify admins/managers + employee history.
--                                  admin-cancel  : notify employee + admin history.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── 1. create_stock_request() — add employee self-confirmation ────────────────

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

  -- Build item lines
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

  -- Employee self-confirmation (history entry in the bell)
  INSERT INTO public.notifications (user_id, type, title, message, payload, created_by)
  VALUES (
    auth.uid(),
    'stock_request_sent',
    '📤 Demande de stock envoyée',
    E'Votre demande a été envoyée à l\'admin :\n' || v_lines,
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
  v_req      public.stock_requests%ROWTYPE;
  v_emp_name text;
  v_adm_name text;
  v_admin    RECORD;
  v_is_admin boolean;
BEGIN
  SELECT * INTO v_req FROM public.stock_requests WHERE id = p_request_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'DEMANDE_INTROUVABLE';
  END IF;

  v_is_admin := EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND role IN ('admin', 'manager')
  );

  -- Employee can only cancel their own pending/preparing requests
  IF v_req.employee_id = auth.uid() AND NOT v_is_admin THEN
    IF v_req.status NOT IN ('pending', 'preparing') THEN
      RAISE EXCEPTION 'ANNULATION_IMPOSSIBLE: statut actuel est %', v_req.status;
    END IF;
  ELSIF NOT v_is_admin THEN
    RAISE EXCEPTION 'PERMISSION_DENIED';
  END IF;

  UPDATE public.stock_requests
  SET status = 'cancelled', updated_at = now()
  WHERE id = p_request_id;

  -- Build employee display name (for admin-cancel notification message)
  SELECT COALESCE(full_name, email, v_req.employee_id::text)
  INTO v_emp_name
  FROM public.profiles WHERE id = v_req.employee_id;

  -- Build admin display name (for employee-cancel notification message)
  SELECT COALESCE(full_name, email, auth.uid()::text)
  INTO v_adm_name
  FROM public.profiles WHERE id = auth.uid();

  IF v_req.employee_id = auth.uid() AND NOT v_is_admin THEN
    -- Employee cancelled: notify admins/managers + add employee history entry

    -- Notify admins/managers
    FOR v_admin IN
      SELECT id FROM public.profiles WHERE role IN ('admin', 'manager')
    LOOP
      INSERT INTO public.notifications (user_id, type, title, message, payload, created_by)
      VALUES (
        v_admin.id,
        'stock_request_cancelled',
        '🚫 Demande annulée',
        v_emp_name || E' a annulé sa demande de stock.',
        jsonb_build_object('request_id', p_request_id, 'employee_id', auth.uid()),
        auth.uid()
      );
    END LOOP;

    -- Employee history entry
    INSERT INTO public.notifications (user_id, type, title, message, payload, created_by)
    VALUES (
      auth.uid(),
      'stock_request_cancelled',
      '🚫 Demande annulée',
      'Vous avez annulé votre demande de stock.',
      jsonb_build_object('request_id', p_request_id),
      auth.uid()
    );

  ELSE
    -- Admin/manager cancelled: notify employee + add admin history entry

    -- Notify the requesting employee
    INSERT INTO public.notifications (user_id, type, title, message, payload, created_by)
    VALUES (
      v_req.employee_id,
      'stock_request_cancelled',
      '🚫 Demande annulée',
      'Votre demande de stock a été annulée par ' || v_adm_name || '.',
      jsonb_build_object('request_id', p_request_id),
      auth.uid()
    );

    -- Admin history entry
    INSERT INTO public.notifications (user_id, type, title, message, payload, created_by)
    VALUES (
      auth.uid(),
      'stock_request_cancelled',
      '🚫 Demande annulée',
      'Vous avez annulé la demande de ' || v_emp_name || '.',
      jsonb_build_object('request_id', p_request_id, 'employee_id', v_req.employee_id),
      auth.uid()
    );

  END IF;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.cancel_stock_request(uuid) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.cancel_stock_request(uuid) TO authenticated;
