/**
 * WebPilot — Client-Side JavaScript (Security Hardened)
 * ======================================================
 * Security features:
 *   - Client-side rate limiting on form submissions (3 per 5 minutes)
 *   - Schema-based input validation (type, length, pattern, required)
 *   - Input sanitization (strip HTML/script tags, trim whitespace)
 *   - Honeypot bot detection
 *   - Selector injection prevention on anchor scroll
 *   - No innerHTML usage (XSS-safe DOM manipulation)
 *   - Graceful 429-style feedback to users
 */

'use strict';

// ══════════════════════════════════════════════════════
// SECTION 1: Scroll Reveal (unchanged functionality)
// ══════════════════════════════════════════════════════
const reveals = document.querySelectorAll('.reveal');

const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.15, rootMargin: '0px 0px -40px 0px' });

reveals.forEach(el => observer.observe(el));

// ══════════════════════════════════════════════════════
// SECTION 2: Sticky Bottom Bar on Scroll
// ══════════════════════════════════════════════════════
const bottomBar = document.getElementById('bottomBar');

window.addEventListener('scroll', () => {
  const scrollY = window.scrollY;

  // Show/hide sticky bottom bar after scrolling past hero
  if (bottomBar) {
    if (scrollY > window.innerHeight * 0.6) {
      bottomBar.classList.add('visible');
    } else {
      bottomBar.classList.remove('visible');
    }
  }
}, { passive: true });

// ══════════════════════════════════════════════════════
// SECTION 3: Smooth Anchor Scroll (HARDENED)
// SECURITY: Prevent selector injection — only allow
// href values that match #[a-zA-Z0-9_-]+ pattern
// ══════════════════════════════════════════════════════
const SAFE_ANCHOR_RE = /^#[a-zA-Z][a-zA-Z0-9_-]*$/;

document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', (e) => {
    const href = anchor.getAttribute('href');

    // SECURITY: Reject any href that doesn't match a safe ID pattern
    // This prevents CSS selector injection via crafted href attributes
    if (!SAFE_ANCHOR_RE.test(href)) return;

    const target = document.getElementById(href.slice(1));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// ══════════════════════════════════════════════════════
// SECTION 5: Input Sanitization Utilities
// ══════════════════════════════════════════════════════

/**
 * SECURITY: Strip HTML tags to prevent stored XSS.
 * Uses a temporary div with textContent (not innerHTML) to
 * avoid executing any injected scripts.
 */
function sanitizeString(input) {
  if (typeof input !== 'string') return '';
  // Trim leading/trailing whitespace
  let cleaned = input.trim();
  // Remove HTML tags (defense in depth — server should also sanitize)
  cleaned = cleaned.replace(/<[^>]*>/g, '');
  // Remove null bytes
  cleaned = cleaned.replace(/\0/g, '');
  return cleaned;
}

/**
 * SECURITY: Validate an email address format.
 * Follows RFC 5322 simplified pattern — rejects obviously bad input.
 */
function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  // Max length per RFC 5321
  if (email.length > 254) return false;
  // Basic structural check (not exhaustive, but catches abuse)
  const EMAIL_RE = /^[^\s@<>()[\]\\,;:]+@[^\s@<>()[\]\\,;:]+\.[^\s@<>()[\]\\,;:]{2,}$/;
  return EMAIL_RE.test(email);
}

// ══════════════════════════════════════════════════════
// SECTION 6: Schema-Based Form Validation
// SECURITY: Define expected fields, types, lengths.
// Reject any unexpected fields or values.
// ══════════════════════════════════════════════════════

const FORM_SCHEMA = {
  name: {
    type: 'string',
    required: true,
    minLength: 1,
    maxLength: 100,
    // SECURITY: Allow letters, spaces, hyphens, apostrophes, periods (international names)
    pattern: /^[\p{L}\p{M}\s'.,-]+$/u,
    errorMessage: 'Please enter a valid name (1–100 characters, letters only).'
  },
  email: {
    type: 'email',
    required: true,
    minLength: 5,
    maxLength: 254,
    // Validated via isValidEmail()
    errorMessage: 'Please enter a valid email address.'
  },
  message: {
    type: 'string',
    required: true,
    minLength: 10,
    maxLength: 5000,
    errorMessage: 'Please enter a message (10–5,000 characters).'
  }
};

// Known allowed field names (reject unexpected fields)
const ALLOWED_FIELDS = new Set(['name', 'email', 'message', '_gotcha']);

/**
 * Validate a single field value against its schema definition.
 * Returns { valid: boolean, error: string | null }
 */
function validateField(fieldName, value, schema) {
  // SECURITY: Type check
  if (typeof value !== 'string') {
    return { valid: false, error: `${fieldName} must be a string.` };
  }

  const sanitized = sanitizeString(value);

  // Required check
  if (schema.required && sanitized.length === 0) {
    return { valid: false, error: schema.errorMessage };
  }

  // Length checks
  if (sanitized.length < (schema.minLength || 0)) {
    return { valid: false, error: schema.errorMessage };
  }
  if (sanitized.length > (schema.maxLength || Infinity)) {
    return { valid: false, error: schema.errorMessage };
  }

  // Email-specific validation
  if (schema.type === 'email' && !isValidEmail(sanitized)) {
    return { valid: false, error: schema.errorMessage };
  }

  // Pattern check (for name field, etc.)
  if (schema.pattern && !schema.pattern.test(sanitized)) {
    return { valid: false, error: schema.errorMessage };
  }

  return { valid: true, error: null };
}

// ══════════════════════════════════════════════════════
// SECTION 7: Client-Side Rate Limiter
// SECURITY: Prevent form spam even if server rate
// limiting is bypassed. Uses localStorage timestamps.
// ══════════════════════════════════════════════════════

const RATE_LIMIT_KEY = 'wp_form_submissions';
const RATE_LIMIT_MAX = 3;          // max submissions
const RATE_LIMIT_WINDOW_MS = 300000; // per 5 minutes

/**
 * Check if the user has exceeded client-side rate limits.
 * Returns { allowed: boolean, retryAfterMs: number }
 */
function checkRateLimit() {
  const now = Date.now();
  let timestamps = [];

  try {
    const stored = localStorage.getItem(RATE_LIMIT_KEY);
    if (stored) {
      timestamps = JSON.parse(stored);
      // SECURITY: Validate stored data is an array of numbers
      if (!Array.isArray(timestamps)) timestamps = [];
      timestamps = timestamps.filter(t => typeof t === 'number' && t > now - RATE_LIMIT_WINDOW_MS);
    }
  } catch {
    // SECURITY: If localStorage is corrupted or unavailable, reset
    timestamps = [];
  }

  if (timestamps.length >= RATE_LIMIT_MAX) {
    const oldest = Math.min(...timestamps);
    const retryAfterMs = (oldest + RATE_LIMIT_WINDOW_MS) - now;
    return { allowed: false, retryAfterMs: Math.max(retryAfterMs, 1000) };
  }

  return { allowed: true, retryAfterMs: 0 };
}

/**
 * Record a form submission timestamp for rate limiting.
 */
function recordSubmission() {
  const now = Date.now();
  let timestamps = [];
  try {
    const stored = localStorage.getItem(RATE_LIMIT_KEY);
    if (stored) {
      timestamps = JSON.parse(stored);
      if (!Array.isArray(timestamps)) timestamps = [];
      timestamps = timestamps.filter(t => typeof t === 'number' && t > now - RATE_LIMIT_WINDOW_MS);
    }
    timestamps.push(now);
    localStorage.setItem(RATE_LIMIT_KEY, JSON.stringify(timestamps));
  } catch {
    // SECURITY: Fail open — don't block the user if storage is unavailable
  }
}

// ══════════════════════════════════════════════════════
// SECTION 8: Form Submission Handler (HARDENED)
// ══════════════════════════════════════════════════════

const contactForm = document.getElementById('contactForm');
const feedbackEl = document.getElementById('formFeedback');
const submitBtn = document.getElementById('submitBtn');

/**
 * Show feedback message to the user (no innerHTML — XSS safe).
 */
function showFeedback(message, isError) {
  feedbackEl.textContent = message;
  feedbackEl.className = isError ? 'form-feedback form-feedback--error' : 'form-feedback form-feedback--success';
  // Auto-clear after 8 seconds
  setTimeout(() => {
    feedbackEl.textContent = '';
    feedbackEl.className = 'form-feedback';
  }, 8000);
}

if (contactForm) {
  contactForm.addEventListener('submit', (e) => {
    e.preventDefault();

    // ── Honeypot check ──
    // SECURITY: If the hidden _gotcha field is filled, a bot submitted the form
    const honeypot = contactForm.querySelector('#_gotcha');
    if (honeypot && honeypot.value.length > 0) {
      // Silently reject — don't reveal honeypot to bots
      showFeedback('Message sent! We\'ll be in touch soon.', false);
      return;
    }

    // ── Client-side rate limit check ──
    const rateCheck = checkRateLimit();
    if (!rateCheck.allowed) {
      const retrySeconds = Math.ceil(rateCheck.retryAfterMs / 1000);
      // SECURITY: Graceful 429-style feedback
      showFeedback(
        `You've sent too many messages. Please try again in ${retrySeconds} seconds.`,
        true
      );
      return;
    }

    // ── Collect and validate form data ──
    const formData = new FormData(contactForm);
    const values = {};
    const errors = [];

    // SECURITY: Check for unexpected fields (reject unknown keys)
    for (const [key] of formData.entries()) {
      if (!ALLOWED_FIELDS.has(key)) {
        showFeedback('Invalid form submission. Please refresh and try again.', true);
        return;
      }
    }

    // Validate each expected field against the schema
    for (const [fieldName, schema] of Object.entries(FORM_SCHEMA)) {
      const rawValue = formData.get(fieldName) || '';
      const sanitized = sanitizeString(rawValue);
      values[fieldName] = sanitized;

      const result = validateField(fieldName, rawValue, schema);
      if (!result.valid) {
        errors.push(result.error);
      }
    }

    // Show first validation error (one at a time — better UX)
    if (errors.length > 0) {
      showFeedback(errors[0], true);
      return;
    }

    // ── Submit via fetch (replaces native form POST) ──
    submitBtn.disabled = true;
    submitBtn.textContent = 'Sending...';

    // Build sanitized FormData (only allowed fields with clean values)
    const cleanData = new FormData();
    cleanData.append('name', values.name);
    cleanData.append('email', values.email);
    cleanData.append('message', values.message);

    fetch(contactForm.action, {
      method: 'POST',
      body: cleanData,
      headers: {
        'Accept': 'application/json'
      }
    })
    .then(response => {
      if (response.ok) {
        recordSubmission();
        showFeedback('Message sent! We\'ll be in touch soon.', false);
        contactForm.reset();
      } else if (response.status === 429) {
        // SECURITY: Server-side rate limit hit
        showFeedback('Too many requests. Please wait a moment and try again.', true);
      } else {
        showFeedback('Something went wrong. Please try again later.', true);
      }
    })
    .catch(() => {
      showFeedback('Network error. Please check your connection and try again.', true);
    })
    .finally(() => {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Send Message';
    });
  });
}
