-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Add phone, latitude, longitude columns to clients
-- ─────────────────────────────────────────────────────────────────────────────
-- Idempotent: safe to run on both new and existing databases.
-- Does not drop or alter any existing column.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE public.clients
  ADD COLUMN IF NOT EXISTS phone     text,
  ADD COLUMN IF NOT EXISTS latitude  numeric,
  ADD COLUMN IF NOT EXISTS longitude numeric;
