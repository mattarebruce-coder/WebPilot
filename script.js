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
// SECTION 3: Custom Cursor + Interactions
// Adds: glowing cursor, magnetic buttons, grid spotlight
// ══════════════════════════════════════════════════════
(function() {
  // Skip on touch-only devices
  if (!window.matchMedia('(hover: hover)').matches) return;

  const cursor = document.getElementById('cursor');
  const dot = document.getElementById('cursorDot');
  const glow = document.getElementById('cursorGlow');
  if (!cursor || !dot || !glow) return;

  let mouseX = 0, mouseY = 0;
  let cursorX = 0, cursorY = 0;
  let dotX = 0, dotY = 0;
  let glowX = 0, glowY = 0;
  let isHovering = false;

  // Track mouse position
  document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
  }, { passive: true });

  // Smooth follow animation loop
  function animate() {
    // Outer ring — smooth lag
    cursorX += (mouseX - cursorX) * 0.12;
    cursorY += (mouseY - cursorY) * 0.12;
    cursor.style.left = cursorX + 'px';
    cursor.style.top = cursorY + 'px';

    // Inner dot — fast follow
    dotX += (mouseX - dotX) * 0.6;
    dotY += (mouseY - dotY) * 0.6;
    dot.style.left = dotX + 'px';
    dot.style.top = dotY + 'px';

    // Glow — very slow follow for ambient effect
    glowX += (mouseX - glowX) * 0.05;
    glowY += (mouseY - glowY) * 0.05;
    glow.style.left = glowX + 'px';
    glow.style.top = glowY + 'px';

    requestAnimationFrame(animate);
  }
  animate();

  // ── Hover detection for interactive elements ──
  const interactiveSelectors = 'a, button, .btn, .card, .process-card, .stat-card, .cta-card, .bottom-pill';
  const inputSelectors = 'input, textarea';

  document.addEventListener('mouseover', (e) => {
    const target = e.target.closest(interactiveSelectors);
    const inputTarget = e.target.closest(inputSelectors);

    if (inputTarget) {
      cursor.classList.add('text-hover');
      cursor.classList.remove('hover');
      dot.style.opacity = '0';
    } else if (target) {
      cursor.classList.add('hover');
      cursor.classList.remove('text-hover');
      dot.style.opacity = '1';
      isHovering = true;
    }
  }, { passive: true });

  document.addEventListener('mouseout', (e) => {
    const target = e.target.closest(interactiveSelectors);
    const inputTarget = e.target.closest(inputSelectors);

    if (target || inputTarget) {
      cursor.classList.remove('hover', 'text-hover');
      dot.style.opacity = '1';
      isHovering = false;
    }
  }, { passive: true });

  // ── Click feedback ──
  document.addEventListener('mousedown', () => {
    cursor.classList.add('clicking');
  });
  document.addEventListener('mouseup', () => {
    cursor.classList.remove('clicking');
  });

  // ── Magnetic effect on buttons ──
  const magneticEls = document.querySelectorAll('.btn, .bottom-pill, .nav-cta');
  const MAGNETIC_STRENGTH = 0.3;
  const MAGNETIC_DISTANCE = 120;

  magneticEls.forEach(el => {
    el.addEventListener('mousemove', (e) => {
      const rect = el.getBoundingClientRect();
      const centerX = rect.left + rect.width / 2;
      const centerY = rect.top + rect.height / 2;
      const distX = e.clientX - centerX;
      const distY = e.clientY - centerY;
      const dist = Math.sqrt(distX * distX + distY * distY);

      if (dist < MAGNETIC_DISTANCE) {
        const pullX = distX * MAGNETIC_STRENGTH;
        const pullY = distY * MAGNETIC_STRENGTH;
        el.style.transform = `translate(${pullX}px, ${pullY}px)`;
      }
    }, { passive: true });

    el.addEventListener('mouseleave', () => {
      el.style.transform = '';
    }, { passive: true });
  });

  // ── Card tilt effect (3D) ──
  const tiltCards = document.querySelectorAll('.card, .process-card, .stat-card, .cta-card');
  const TILT_MAX = 8; // degrees

  tiltCards.forEach(card => {
    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width;
      const y = (e.clientY - rect.top) / rect.height;
      const rotateX = (0.5 - y) * TILT_MAX;
      const rotateY = (x - 0.5) * TILT_MAX;

      card.style.transform = `perspective(600px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-4px)`;
    }, { passive: true });

    card.addEventListener('mouseleave', () => {
      card.style.transform = '';
    }, { passive: true });
  });

  // ── Grid spotlight — brighten grid lines near cursor ──
  const gridLines = document.querySelector('.grid-bg-lines');
  if (gridLines) {
    document.addEventListener('mousemove', (e) => {
      gridLines.style.maskImage = `radial-gradient(circle 250px at ${e.clientX}px ${e.clientY}px, rgba(0,0,0,1) 0%, rgba(0,0,0,0.15) 100%)`;
      gridLines.style.webkitMaskImage = `radial-gradient(circle 250px at ${e.clientX}px ${e.clientY}px, rgba(0,0,0,1) 0%, rgba(0,0,0,0.15) 100%)`;
    }, { passive: true });
  }

  // ── Hide cursor when leaving window ──
  document.addEventListener('mouseleave', () => {
    cursor.style.opacity = '0';
    dot.style.opacity = '0';
    glow.style.opacity = '0';
  });

  document.addEventListener('mouseenter', () => {
    cursor.style.opacity = '1';
    dot.style.opacity = '1';
    glow.style.opacity = '1';
  });
})();

// ══════════════════════════════════════════════════════
// SECTION 4: Smooth Anchor Scroll (HARDENED)
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
