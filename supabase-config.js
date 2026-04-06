/*
 * ══════════════════════════════════════════════════════════════════════
 *  WebPilot — Supabase Configuration
 *
 *  SETUP INSTRUCTIONS:
 *  1. Create a Supabase project at https://supabase.com
 *  2. Run the SQL schema below in the Supabase SQL Editor
 *  3. Set your Supabase URL and anon key before loading this script:
 *
 *     <script>
 *       window.__SUPABASE_URL__ = 'https://YOUR_PROJECT.supabase.co';
 *       window.__SUPABASE_KEY__ = 'YOUR_ANON_KEY_HERE';
 *     </script>
 *     <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
 *     <script src="supabase-config.js?v=3"></script>
 *
 *  4. Create an admin user in Supabase Auth (Authentication > Users > Add User)
 *     Use email/password — this user will log in to admin.html
 *
 * ══════════════════════════════════════════════════════════════════════
 *
 *  SQL SCHEMA — Paste this into Supabase SQL Editor and run it:
 *
 *  ────────────────────────────────────────────────────────────────────
 *
 *  -- Enable UUID extension
 *  CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
 *
 *  -- ══ Clients Table ══
 *  CREATE TABLE clients (
 *    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
 *    name TEXT NOT NULL,
 *    email TEXT NOT NULL UNIQUE,
 *    phone TEXT DEFAULT '',
 *    company TEXT DEFAULT '',
 *    created_at TIMESTAMPTZ DEFAULT NOW(),
 *    updated_at TIMESTAMPTZ DEFAULT NOW()
 *  );
 *
 *  -- ══ Projects Table ══
 *  CREATE TABLE projects (
 *    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
 *    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
 *    project_name TEXT NOT NULL,
 *    project_type TEXT NOT NULL DEFAULT 'Website'
 *      CHECK (project_type IN ('Website', 'Redesign', 'Maintenance', 'SEO', 'Other')),
 *    status TEXT NOT NULL DEFAULT 'New'
 *      CHECK (status IN ('New', 'In Progress', 'Review', 'Revision', 'Complete', 'On Hold')),
 *    priority TEXT NOT NULL DEFAULT 'Medium'
 *      CHECK (priority IN ('Low', 'Medium', 'High', 'Urgent')),
 *    progress INTEGER DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
 *    start_date DATE,
 *    deadline DATE,
 *    budget NUMERIC(10,2) DEFAULT 0,
 *    amount_paid NUMERIC(10,2) DEFAULT 0,
 *    payment_status TEXT NOT NULL DEFAULT 'Unpaid'
 *      CHECK (payment_status IN ('Unpaid', 'Partial', 'Paid')),
 *    invoice_link TEXT DEFAULT '',
 *    file_links TEXT DEFAULT '',
 *    created_at TIMESTAMPTZ DEFAULT NOW(),
 *    updated_at TIMESTAMPTZ DEFAULT NOW()
 *  );
 *
 *  -- ══ Update Notes Table ══
 *  CREATE TABLE update_notes (
 *    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
 *    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 *    note TEXT NOT NULL,
 *    created_at TIMESTAMPTZ DEFAULT NOW()
 *  );
 *
 *  -- ══ Indexes ══
 *  CREATE INDEX idx_projects_client_id ON projects(client_id);
 *  CREATE INDEX idx_projects_status ON projects(status);
 *  CREATE INDEX idx_update_notes_project_id ON update_notes(project_id);
 *  CREATE INDEX idx_clients_email ON clients(email);
 *
 *  -- ══ Updated_at trigger function ══
 *  CREATE OR REPLACE FUNCTION update_updated_at()
 *  RETURNS TRIGGER AS $$
 *  BEGIN
 *    NEW.updated_at = NOW();
 *    RETURN NEW;
 *  END;
 *  $$ LANGUAGE plpgsql;
 *
 *  CREATE TRIGGER clients_updated_at
 *    BEFORE UPDATE ON clients
 *    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
 *
 *  CREATE TRIGGER projects_updated_at
 *    BEFORE UPDATE ON projects
 *    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
 *
 *  -- ══ Row Level Security ══
 *
 *  -- Enable RLS on all tables
 *  ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
 *  ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
 *  ALTER TABLE update_notes ENABLE ROW LEVEL SECURITY;
 *
 *  -- Admin policies: authenticated users (your admin account) get full access
 *  CREATE POLICY "Admin full access on clients"
 *    ON clients FOR ALL
 *    USING (auth.role() = 'authenticated')
 *    WITH CHECK (auth.role() = 'authenticated');
 *
 *  CREATE POLICY "Admin full access on projects"
 *    ON projects FOR ALL
 *    USING (auth.role() = 'authenticated')
 *    WITH CHECK (auth.role() = 'authenticated');
 *
 *  CREATE POLICY "Admin full access on update_notes"
 *    ON update_notes FOR ALL
 *    USING (auth.role() = 'authenticated')
 *    WITH CHECK (auth.role() = 'authenticated');
 *
 *  -- Client-facing policies: anon users can read their own project data by email
 *  -- These use a function that checks the client email against a request parameter
 *  CREATE OR REPLACE FUNCTION public.get_client_email()
 *  RETURNS TEXT AS $$
 *    SELECT COALESCE(
 *      current_setting('request.headers', true)::json->>'x-client-email',
 *      ''
 *    );
 *  $$ LANGUAGE sql STABLE;
 *
 *  -- Anon can read clients matching their email (passed via RPC or header)
 *  CREATE POLICY "Anon read own client"
 *    ON clients FOR SELECT
 *    USING (
 *      auth.role() = 'anon'
 *      AND LOWER(email) = LOWER(public.get_client_email())
 *    );
 *
 *  -- Anon can read projects belonging to their client record
 *  CREATE POLICY "Anon read own projects"
 *    ON projects FOR SELECT
 *    USING (
 *      auth.role() = 'anon'
 *      AND client_id IN (
 *        SELECT id FROM clients
 *        WHERE LOWER(email) = LOWER(public.get_client_email())
 *      )
 *    );
 *
 *  -- Anon can read update notes for their own projects
 *  CREATE POLICY "Anon read own update_notes"
 *    ON update_notes FOR SELECT
 *    USING (
 *      auth.role() = 'anon'
 *      AND project_id IN (
 *        SELECT p.id FROM projects p
 *        JOIN clients c ON c.id = p.client_id
 *        WHERE LOWER(c.email) = LOWER(public.get_client_email())
 *      )
 *    );
 *
 *  -- ══ RPC function for client status lookup (simpler alternative) ══
 *  -- This bypasses RLS by using SECURITY DEFINER, but only returns
 *  -- data for the provided email. Use this from the status page.
 *
 *  CREATE OR REPLACE FUNCTION public.get_client_status(client_email TEXT)
 *  RETURNS JSON AS $$
 *  DECLARE
 *    result JSON;
 *  BEGIN
 *    SELECT json_build_object(
 *      'client', json_build_object(
 *        'name', c.name,
 *        'email', c.email,
 *        'company', c.company
 *      ),
 *      'projects', COALESCE((
 *        SELECT json_agg(
 *          json_build_object(
 *            'id', p.id,
 *            'project_name', p.project_name,
 *            'project_type', p.project_type,
 *            'status', p.status,
 *            'progress', p.progress,
 *            'start_date', p.start_date,
 *            'deadline', p.deadline,
 *            'payment_status', p.payment_status,
 *            'notes', COALESCE((
 *              SELECT json_agg(
 *                json_build_object(
 *                  'note', n.note,
 *                  'created_at', n.created_at
 *                ) ORDER BY n.created_at DESC
 *              )
 *              FROM update_notes n
 *              WHERE n.project_id = p.id
 *            ), '[]'::json)
 *          )
 *        )
 *        FROM projects p
 *        WHERE p.client_id = c.id
 *      ), '[]'::json)
 *    ) INTO result
 *    FROM clients c
 *    WHERE LOWER(c.email) = LOWER(client_email);
 *
 *    RETURN result;
 *  END;
 *  $$ LANGUAGE plpgsql SECURITY DEFINER;
 *
 *  ────────────────────────────────────────────────────────────────────
 *  END OF SQL SCHEMA
 *  ────────────────────────────────────────────────────────────────────
 */

// ══════════════════════════════════════════════════════════════════════
//  Supabase Client Initialization
//
//  SECURITY NOTE — API Key Handling (OWASP A02:2021)
//  ──────────────────────────────────────────────────
//  The key below is the Supabase "anon" (public) key. It is DESIGNED
//  to be exposed in client-side code — similar to a Firebase apiKey.
//  It can only perform operations allowed by Row Level Security (RLS)
//  policies defined in the database schema above.
//
//  ⚠ The "service_role" key must NEVER appear in client-side code.
//    It bypasses RLS and grants full database access.
//
//  For production deployments with a build step, inject these values
//  via environment variables at build time:
//    VITE_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_URL
//    VITE_SUPABASE_KEY / NEXT_PUBLIC_SUPABASE_KEY
//
//  For this static GitHub Pages site, the anon key is safe to include
//  because RLS is the authoritative access-control layer.
// ══════════════════════════════════════════════════════════════════════

(function () {
  'use strict';

  // ── Configuration (single source of truth) ──
  // If window overrides are set (for testing/staging), prefer those.
  // Otherwise use the production values below.
  var SUPABASE_URL = window.__SUPABASE_URL__ ||
    'https://foajrtjogogbpjvddlks.supabase.co';
  var SUPABASE_KEY = window.__SUPABASE_KEY__ ||
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZvYWpydGpvZ29nYnBqdmRkbGtzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzU0ODAzNTksImV4cCI6MjA5MTA1NjM1OX0.ETc3FoUiwRRsdHwvjyZjJUO_qDRCj8d-Z2GRdTaGuiw';

  // SECURITY: Validate URL format before use
  if (SUPABASE_URL && !/^https:\/\/[a-z0-9-]+\.supabase\.co\/?$/i.test(SUPABASE_URL)) {
    console.error('[WebPilot] Invalid Supabase URL format — possible tampering');
    SUPABASE_URL = '';
  }

  // SECURITY: Validate key is a JWT (three base64 segments)
  if (SUPABASE_KEY && !/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(SUPABASE_KEY)) {
    console.error('[WebPilot] Invalid Supabase key format — possible tampering');
    SUPABASE_KEY = '';
  }

  if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.error(
      '[WebPilot] Supabase not configured. Check supabase-config.js'
    );
  }

  // Create the Supabase client (supabase-js v2 loaded from CDN exposes 'supabase' global)
  var client = null;
  if (window.supabase && window.supabase.createClient && SUPABASE_URL && SUPABASE_KEY) {
    client = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);
  }

  // Expose on window for use by admin.html and status.html
  window.WebPilotSupabase = client;

  // Helper: get current authenticated user (admin)
  window.WebPilotGetUser = async function () {
    if (!client) return null;
    var { data } = await client.auth.getUser();
    return data && data.user ? data.user : null;
  };

  // Helper: sign in with email/password (admin)
  window.WebPilotSignIn = async function (email, password) {
    if (!client) throw new Error('Supabase not configured');
    var { data, error } = await client.auth.signInWithPassword({ email: email, password: password });
    if (error) throw error;
    return data;
  };

  // Helper: sign out (admin)
  window.WebPilotSignOut = async function () {
    if (!client) return;
    await client.auth.signOut();
  };

  // Helper: fetch client status by email (uses RPC, works with anon key)
  window.WebPilotGetClientStatus = async function (email) {
    if (!client) throw new Error('Supabase not configured');
    var { data, error } = await client.rpc('get_client_status', { client_email: email });
    if (error) throw error;
    return data;
  };

})();
