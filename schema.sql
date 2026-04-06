-- ══════════════════════════════════════════════════════════════
-- WebPilot CRM — Supabase Database Schema
-- Paste this entire file into Supabase SQL Editor and click "Run"
-- ══════════════════════════════════════════════════════════════

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ══ Clients Table ══
CREATE TABLE clients (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  phone TEXT DEFAULT '',
  company TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ══ Projects Table ══
CREATE TABLE projects (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  project_name TEXT NOT NULL,
  project_type TEXT NOT NULL DEFAULT 'Website'
    CHECK (project_type IN ('Website', 'Redesign', 'Maintenance', 'SEO', 'Other')),
  status TEXT NOT NULL DEFAULT 'New'
    CHECK (status IN ('New', 'In Progress', 'Review', 'Revision', 'Complete', 'On Hold')),
  priority TEXT NOT NULL DEFAULT 'Medium'
    CHECK (priority IN ('Low', 'Medium', 'High', 'Urgent')),
  progress INTEGER DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
  start_date DATE,
  deadline DATE,
  budget NUMERIC(10,2) DEFAULT 0,
  amount_paid NUMERIC(10,2) DEFAULT 0,
  payment_status TEXT NOT NULL DEFAULT 'Unpaid'
    CHECK (payment_status IN ('Unpaid', 'Partial', 'Paid')),
  invoice_link TEXT DEFAULT '',
  file_links TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ══ Update Notes Table ══
CREATE TABLE update_notes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  note TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ══ Indexes ══
CREATE INDEX idx_projects_client_id ON projects(client_id);
CREATE INDEX idx_projects_status ON projects(status);
CREATE INDEX idx_update_notes_project_id ON update_notes(project_id);
CREATE INDEX idx_clients_email ON clients(email);

-- ══ Updated_at trigger function ══
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER clients_updated_at
  BEFORE UPDATE ON clients
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER projects_updated_at
  BEFORE UPDATE ON projects
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ══ Row Level Security ══

-- Enable RLS on all tables
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE update_notes ENABLE ROW LEVEL SECURITY;

-- Admin policies: authenticated users (your admin account) get full access
CREATE POLICY "Admin full access on clients"
  ON clients FOR ALL
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');

CREATE POLICY "Admin full access on projects"
  ON projects FOR ALL
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');

CREATE POLICY "Admin full access on update_notes"
  ON update_notes FOR ALL
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');

-- Client-facing policies: anon users can read their own project data by email
CREATE OR REPLACE FUNCTION public.get_client_email()
RETURNS TEXT AS $$
  SELECT COALESCE(
    current_setting('request.headers', true)::json->>'x-client-email',
    ''
  );
$$ LANGUAGE sql STABLE;

-- Anon can read clients matching their email (passed via RPC or header)
CREATE POLICY "Anon read own client"
  ON clients FOR SELECT
  USING (
    auth.role() = 'anon'
    AND LOWER(email) = LOWER(public.get_client_email())
  );

-- Anon can read projects belonging to their client record
CREATE POLICY "Anon read own projects"
  ON projects FOR SELECT
  USING (
    auth.role() = 'anon'
    AND client_id IN (
      SELECT id FROM clients
      WHERE LOWER(email) = LOWER(public.get_client_email())
    )
  );

-- Anon can read update notes for their own projects
CREATE POLICY "Anon read own update_notes"
  ON update_notes FOR SELECT
  USING (
    auth.role() = 'anon'
    AND project_id IN (
      SELECT p.id FROM projects p
      JOIN clients c ON c.id = p.client_id
      WHERE LOWER(c.email) = LOWER(public.get_client_email())
    )
  );

-- ══ RPC function for client status lookup ══
-- This bypasses RLS by using SECURITY DEFINER, but only returns
-- data for the provided email. Used by the status page.

CREATE OR REPLACE FUNCTION public.get_client_status(client_email TEXT)
RETURNS JSON AS $$
DECLARE
  result JSON;
BEGIN
  SELECT json_build_object(
    'client', json_build_object(
      'name', c.name,
      'email', c.email,
      'company', c.company
    ),
    'projects', COALESCE((
      SELECT json_agg(
        json_build_object(
          'id', p.id,
          'project_name', p.project_name,
          'project_type', p.project_type,
          'status', p.status,
          'progress', p.progress,
          'start_date', p.start_date,
          'deadline', p.deadline,
          'payment_status', p.payment_status,
          'notes', COALESCE((
            SELECT json_agg(
              json_build_object(
                'note', n.note,
                'created_at', n.created_at
              ) ORDER BY n.created_at DESC
            )
            FROM update_notes n
            WHERE n.project_id = p.id
          ), '[]'::json)
        )
      )
      FROM projects p
      WHERE p.client_id = c.id
    ), '[]'::json)
  ) INTO result
  FROM clients c
  WHERE LOWER(c.email) = LOWER(client_email);

  RETURN result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
