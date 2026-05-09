-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Supabase Storage bucket for fuel receipt photos
-- ─────────────────────────────────────────────────────────────────────────────
-- Creates a private bucket "fuel-receipts" where employees upload their pump/
-- ticket photos.  Storage paths follow the pattern:
--   {employee_id}/{yyyy-mm}/{timestamp}.{ext}
-- so that row-level Storage policies can restrict read/write to the owning
-- employee while admin/manager can read everything.
-- ─────────────────────────────────────────────────────────────────────────────

-- 1. Create the private bucket (ignored if it already exists)
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'fuel-receipts',
  'fuel-receipts',
  false,
  5242880,
  ARRAY['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/heic', 'image/heif']
)
ON CONFLICT (id) DO NOTHING;

-- 2. Drop old policies if they exist (idempotent re-run)
DROP POLICY IF EXISTS "fuel_receipts_insert" ON storage.objects;
DROP POLICY IF EXISTS "fuel_receipts_select" ON storage.objects;
DROP POLICY IF EXISTS "fuel_receipts_delete" ON storage.objects;

-- 3. INSERT: authenticated employees may upload only into their own folder
--    Path prefix: {employee_id}/…
CREATE POLICY "fuel_receipts_insert"
  ON storage.objects FOR INSERT
  TO authenticated
  WITH CHECK (
    bucket_id = 'fuel-receipts'
    AND name LIKE (auth.uid()::text || '/%')
  );

-- 4. SELECT: employees see their own photos; admin/manager see all
CREATE POLICY "fuel_receipts_select"
  ON storage.objects FOR SELECT
  TO authenticated
  USING (
    bucket_id = 'fuel-receipts'
    AND (
      name LIKE (auth.uid()::text || '/%')
      OR public.is_admin_or_manager()
    )
  );

-- 5. DELETE: only admin/manager may remove photos
CREATE POLICY "fuel_receipts_delete"
  ON storage.objects FOR DELETE
  TO authenticated
  USING (
    bucket_id = 'fuel-receipts'
    AND public.is_admin_or_manager()
  );
