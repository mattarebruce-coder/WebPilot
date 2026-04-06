/*
 * ══════════════════════════════════════════════════════════════════════
 *  WebPilot — Security Utilities (Shared)
 *
 *  Provides client-side security hardening for all CRM pages:
 *    • Sliding-window rate limiter (IP-simulated via localStorage)
 *    • Input sanitization (HTML entity encoding, tag stripping)
 *    • Schema-based validation (type checks, length limits, patterns)
 *    • Field whitelisting (reject unexpected fields)
 *
 *  SECURITY NOTE: Client-side checks are a UX layer, NOT a trust
 *  boundary. Supabase Row Level Security (RLS) is the authoritative
 *  enforcement layer. These checks reduce noise and block casual abuse.
 *
 *  OWASP references:
 *    • A03:2021 — Injection        (sanitization, parameterised queries)
 *    • A04:2021 — Insecure Design  (rate limiting, schema validation)
 *    • A07:2021 — XSS              (HTML entity encoding)
 * ══════════════════════════════════════════════════════════════════════
 */

'use strict';

window.WebPilotSecurity = (function () {

  // ═══════════════════════════════════════════
  // SECTION 1: Client-Side Rate Limiter
  // Sliding window stored in localStorage.
  // Each action has its own bucket (login, save, lookup, etc.)
  // Returns { allowed: true } or { allowed: false, retryAfter: seconds }
  // ═══════════════════════════════════════════

  /**
   * @param {string} action   — unique key for this action (e.g. 'login', 'save')
   * @param {number} max      — max attempts in the window
   * @param {number} windowMs — window duration in milliseconds
   */
  function RateLimiter(action, max, windowMs) {
    this._key = 'wp_rl_' + action;
    this._max = max;
    this._window = windowMs;
  }

  RateLimiter.prototype.check = function () {
    var now = Date.now();
    var stored;
    try {
      stored = JSON.parse(localStorage.getItem(this._key) || '[]');
      // SECURITY: validate stored data is an array of numbers
      if (!Array.isArray(stored)) stored = [];
      stored = stored.filter(function (ts) {
        return typeof ts === 'number' && !isNaN(ts);
      });
    } catch (e) {
      stored = [];
    }

    // Slide window — remove expired entries
    var windowStart = now - this._window;
    stored = stored.filter(function (ts) { return ts > windowStart; });

    if (stored.length >= this._max) {
      var oldestValid = stored[0];
      var retryAfter = Math.ceil((oldestValid + this._window - now) / 1000);
      return { allowed: false, retryAfter: Math.max(retryAfter, 1) };
    }

    stored.push(now);
    try {
      localStorage.setItem(this._key, JSON.stringify(stored));
    } catch (e) {
      // localStorage full or unavailable — allow the request
    }
    return { allowed: true };
  };

  RateLimiter.prototype.reset = function () {
    try { localStorage.removeItem(this._key); } catch (e) { /* noop */ }
  };

  // ═══════════════════════════════════════════
  // SECTION 2: Input Sanitization
  // ═══════════════════════════════════════════

  var HTML_ENTITIES = {
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;'
  };

  /**
   * Encode HTML entities to prevent XSS when rendering user content.
   * OWASP A07:2021 — Cross-Site Scripting
   */
  function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/[<>&"'/]/g, function (c) { return HTML_ENTITIES[c]; });
  }

  /**
   * Strip HTML tags and trim whitespace.
   * Use for plain-text fields before storing.
   */
  function sanitizeString(str) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/<[^>]*>/g, '')     // strip HTML tags
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // strip control chars
      .trim();
  }

  /**
   * Sanitize a URL string — only allow http(s) schemes.
   * Prevents javascript: and data: URI injection.
   */
  function sanitizeUrl(str) {
    if (typeof str !== 'string' || !str.trim()) return '';
    str = str.trim();
    // SECURITY: only allow http and https schemes
    if (!/^https?:\/\//i.test(str)) return '';
    try {
      var url = new URL(str);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') return '';
      return url.href;
    } catch (e) {
      return '';
    }
  }

  // ═══════════════════════════════════════════
  // SECTION 3: Schema-Based Validation
  // Validates an object against a schema definition.
  // Each field specifies: type, required, minLength, maxLength,
  // pattern, allowedValues, min, max.
  // Returns array of error strings (empty = valid).
  // ═══════════════════════════════════════════

  // Common validation patterns
  var PATTERNS = {
    // SECURITY: restrictive name pattern — unicode letters, spaces, hyphens, apostrophes
    name: /^[\p{L}\s\-'.]+$/u,
    // RFC 5322 simplified — good enough for client-side pre-check
    email: /^[^\s@<>(){}\[\]\\,;:]+@[^\s@<>(){}\[\]\\,;:]+\.[a-zA-Z]{2,}$/,
    // Phone: digits, spaces, hyphens, plus, parens, dots
    phone: /^[\d\s\-+().]*$/,
    // Date: YYYY-MM-DD
    date: /^\d{4}-\d{2}-\d{2}$/,
    // Safe text: no angle brackets (prevents HTML injection in plain text fields)
    safeText: /^[^<>]*$/
  };

  /**
   * Validate a single field value against a rules object.
   * @param {string} value — the field value (always coerced to string)
   * @param {object} rules — { label, type, required, minLength, maxLength,
   *                           pattern, allowedValues, min, max }
   * @returns {string|null} — error message or null if valid
   */
  function validateField(value, rules) {
    var v = (value == null) ? '' : String(value);

    // Required check
    if (rules.required && !v.trim()) {
      return rules.label + ' is required';
    }

    // Optional empty — skip further checks
    if (!v.trim() && !rules.required) return null;

    // Type-specific checks
    switch (rules.type) {
      case 'email':
        if (!PATTERNS.email.test(v)) return 'Invalid email address';
        break;
      case 'url':
        if (v && !sanitizeUrl(v)) return 'Invalid or unsafe URL (only http/https allowed)';
        break;
      case 'tel':
        if (!PATTERNS.phone.test(v)) return 'Invalid phone number format';
        break;
      case 'date':
        if (v && !PATTERNS.date.test(v)) return 'Invalid date format (YYYY-MM-DD)';
        if (v) {
          var d = new Date(v + 'T00:00:00');
          if (isNaN(d.getTime())) return 'Invalid date';
        }
        break;
      case 'number':
        var n = Number(v);
        if (isNaN(n)) return rules.label + ' must be a number';
        if (rules.min !== undefined && n < rules.min) return rules.label + ' must be at least ' + rules.min;
        if (rules.max !== undefined && n > rules.max) return rules.label + ' must be at most ' + rules.max;
        break;
      case 'integer':
        var i = Number(v);
        if (!Number.isInteger(i)) return rules.label + ' must be a whole number';
        if (rules.min !== undefined && i < rules.min) return rules.label + ' must be at least ' + rules.min;
        if (rules.max !== undefined && i > rules.max) return rules.label + ' must be at most ' + rules.max;
        break;
    }

    // Length limits
    if (rules.minLength && v.length < rules.minLength) {
      return rules.label + ' must be at least ' + rules.minLength + ' characters';
    }
    if (rules.maxLength && v.length > rules.maxLength) {
      return rules.label + ' must be under ' + rules.maxLength + ' characters';
    }

    // Regex pattern
    if (rules.pattern && !rules.pattern.test(v)) {
      return rules.label + ' contains invalid characters';
    }

    // Allowed values (enum check)
    if (rules.allowedValues && rules.allowedValues.indexOf(v) === -1) {
      return 'Invalid value for ' + rules.label;
    }

    return null; // valid
  }

  /**
   * Validate an object against a full schema.
   * SECURITY: Rejects unexpected fields (OWASP A04:2021 — mass assignment).
   * @param {object} data   — key/value pairs to validate
   * @param {object} schema — key -> rules mapping
   * @returns {string[]}    — array of error messages (empty = valid)
   */
  function validateSchema(data, schema) {
    var errors = [];
    var allowedFields = Object.keys(schema);

    // SECURITY: reject unexpected fields (mass assignment protection)
    Object.keys(data).forEach(function (key) {
      if (allowedFields.indexOf(key) === -1) {
        errors.push('Unexpected field rejected: ' + escapeHtml(key));
      }
    });

    // Validate each expected field
    allowedFields.forEach(function (key) {
      var err = validateField(data[key], schema[key]);
      if (err) errors.push(err);
    });

    return errors;
  }

  /**
   * Build a data object from form fields, keeping only allowed keys.
   * SECURITY: Prevents mass assignment by whitelisting fields.
   * @param {string[]} allowedKeys — list of allowed field names
   * @param {object}   source      — raw data object
   * @returns {object} — filtered and sanitized object
   */
  function filterFields(allowedKeys, source) {
    var result = {};
    allowedKeys.forEach(function (key) {
      if (source.hasOwnProperty(key)) {
        result[key] = source[key];
      }
    });
    return result;
  }

  // ═══════════════════════════════════════════
  // SECTION 4: Graceful 429 Formatting
  // Human-readable rate limit messages.
  // ═══════════════════════════════════════════

  function formatRetryMessage(retryAfter) {
    if (retryAfter >= 60) {
      var mins = Math.ceil(retryAfter / 60);
      return 'Too many attempts. Please try again in ' + mins + ' minute' + (mins > 1 ? 's' : '') + '.';
    }
    return 'Too many attempts. Please try again in ' + retryAfter + ' second' + (retryAfter > 1 ? 's' : '') + '.';
  }

  // ═══════════════════════════════════════════
  // Public API
  // ═══════════════════════════════════════════

  return {
    RateLimiter: RateLimiter,
    escapeHtml: escapeHtml,
    sanitizeString: sanitizeString,
    sanitizeUrl: sanitizeUrl,
    validateField: validateField,
    validateSchema: validateSchema,
    filterFields: filterFields,
    formatRetryMessage: formatRetryMessage,
    PATTERNS: PATTERNS
  };

})();
