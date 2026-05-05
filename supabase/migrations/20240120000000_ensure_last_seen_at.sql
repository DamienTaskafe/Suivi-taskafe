-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Ensure last_seen_at column exists on profiles (idempotent)
-- ─────────────────────────────────────────────────────────────────────────────
-- This migration is safe to re-run on any project state.
-- The column was introduced in 20240103000000_profiles_and_presence.sql but
-- this ensures any project that skipped that migration also has the column.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;
