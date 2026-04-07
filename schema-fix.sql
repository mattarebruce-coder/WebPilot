-- ══════════════════════════════════════════════════════════════
-- Fix: Function Search Path Mutable
-- Sets search_path to prevent path injection attacks
-- ══════════════════════════════════════════════════════════════

-- Fix get_client_status + add invoice_link, budget, amount_paid for payment display
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
          'budget', p.budget,
          'amount_paid', p.amount_paid,
          'invoice_link', p.invoice_link,
          'notes', COALESCE((
            SELECT json_agg(
              json_build_object(
                'note', n.note,
                'created_at', n.created_at
              ) ORDER BY n.created_at DESC
            )
            FROM public.update_notes n
            WHERE n.project_id = p.id
          ), '[]'::json)
        )
      )
      FROM public.projects p
      WHERE p.client_id = c.id
    ), '[]'::json)
  ) INTO result
  FROM public.clients c
  WHERE LOWER(c.email) = LOWER(client_email);

  RETURN result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public;

-- Fix update_updated_at
CREATE OR REPLACE FUNCTION public.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = public;

-- Fix get_client_email
CREATE OR REPLACE FUNCTION public.get_client_email()
RETURNS TEXT AS $$
  SELECT COALESCE(
    current_setting('request.headers', true)::json->>'x-client-email',
    ''
  );
$$ LANGUAGE sql STABLE
SET search_path = public;
