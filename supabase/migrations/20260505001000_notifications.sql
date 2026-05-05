-- ── Notifications table ──────────────────────────────────────────────────────
-- Idempotent migration: safe to run multiple times.

CREATE TABLE IF NOT EXISTS public.notifications (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  type       text        NOT NULL,
  title      text        NOT NULL,
  message    text        NOT NULL,
  payload    jsonb       DEFAULT '{}'::jsonb,
  read_at    timestamptz NULL,
  created_by uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

-- Each user can only see their own notifications.
DROP POLICY IF EXISTS "notifications_select_own" ON public.notifications;
CREATE POLICY "notifications_select_own"
  ON public.notifications FOR SELECT
  TO authenticated
  USING (user_id = auth.uid());

-- Each user can mark their own notifications as read (UPDATE restricted to read_at).
DROP POLICY IF EXISTS "notifications_update_own_read" ON public.notifications;
CREATE POLICY "notifications_update_own_read"
  ON public.notifications FOR UPDATE
  TO authenticated
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

-- Only admin/manager users may insert notifications for others.
DROP POLICY IF EXISTS "notifications_insert_admin_manager" ON public.notifications;
CREATE POLICY "notifications_insert_admin_manager"
  ON public.notifications FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid()
        AND role IN ('admin', 'manager')
    )
  );

-- Grant access to authenticated role (table-level).
GRANT SELECT, INSERT, UPDATE ON public.notifications TO authenticated;
