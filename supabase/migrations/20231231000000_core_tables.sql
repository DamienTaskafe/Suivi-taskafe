-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: Core business tables
-- ─────────────────────────────────────────────────────────────────────────────
-- Creates the three tables that the app queries immediately after login inside
-- loadCloudData().  None of the subsequent migrations (RLS policies, security
-- hardening passes 1–3D) contain CREATE TABLE statements — they all use
-- ALTER TABLE IF EXISTS and assume these tables already exist.  Without this
-- migration a fresh or reset Supabase environment has no core tables, and
-- every post-login loadCloudData() call fails with a relation-does-not-exist
-- error that surfaces as "Erreur de chargement des données" in the UI.
--
-- Column inventory derived from index.html business logic:
--
--   public.clients
--     id         — uuid primary key, server-generated
--     name       — text NOT NULL (client display name)
--     address    — text, plain-text formatted address (nullable)
--     ice        — text, Moroccan ICE tax identifier (nullable)
--     prices     — jsonb, per-category custom prices
--                  e.g. {"ORO":130,"RIO":135,"ESPRESSO":140,...}
--     created_at — timestamptz, set by the client at insert time
--
--   public.sales
--     id          — uuid primary key, server-generated
--     client_id   — uuid, nullable FK to clients.id
--                   (null when client was created offline and not yet synced,
--                    or when the sale was recorded without a linked client)
--     client_name — text NOT NULL, denormalized display name
--     category    — text NOT NULL (product category: ORO, RIO, ESPRESSO, …)
--     quantity    — numeric NOT NULL
--     unit_price  — numeric NOT NULL
--     total_price — numeric NOT NULL
--     paid        — boolean NOT NULL DEFAULT false
--     created_by  — uuid, nullable FK to auth.users(id)
--                   (pass 3A adds DEFAULT auth.uid(); pass 3B adds NOT NULL)
--     created_at  — timestamptz, set by the client at insert time
--
--   public.stocks
--     category — text PRIMARY KEY
--                The PRIMARY KEY provides the unique constraint required by the
--                ON CONFLICT (category) clause in both the client-side upserts
--                and the trg_sales_adjust_stock trigger (pass 3C).
--     quantity — numeric NOT NULL DEFAULT 0
--
-- All timestamps are WITH TIME ZONE so ordering by created_at is unambiguous
-- regardless of client timezone.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── public.clients ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.clients (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  name       text        NOT NULL,
  address    text,
  ice        text,
  prices     jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);


-- ── public.sales ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.sales (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id   uuid        REFERENCES public.clients(id) ON DELETE SET NULL,
  client_name text        NOT NULL,
  category    text        NOT NULL,
  quantity    numeric     NOT NULL,
  unit_price  numeric     NOT NULL,
  total_price numeric     NOT NULL,
  paid        boolean     NOT NULL DEFAULT false,
  created_by  uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);


-- ── public.stocks ─────────────────────────────────────────────────────────────
-- category is the primary key so that ON CONFLICT (category) upserts work
-- both in the client-side addToStock/setStock paths and in the
-- trg_sales_adjust_stock trigger added in pass 3C.
CREATE TABLE IF NOT EXISTS public.stocks (
  category text    PRIMARY KEY,
  quantity numeric NOT NULL DEFAULT 0
);
