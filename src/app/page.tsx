"use client";
import React, {useEffect, useMemo, useRef, useState} from "react";

// RFC Content from the actual documents
const rfcContent: Record<string, { title: string; status: string; html: string; pdf: string }> = {
  "rfc-001": {
    title: "RFC-001 · LID URI Specification",
    status: "stable",
    pdf: "/docs/lid-rfc-001.pdf",
    html: `
      <div class="space-y-6">
        <div class="border-b border-zinc-200 dark:border-zinc-800 pb-4">
          <h1 class="text-xl font-semibold mb-2">LID-RFC-001: Linkism ID URI Specification</h1>
          <div class="text-xs text-zinc-600 dark:text-zinc-400 space-y-1">
            <div><strong>Status:</strong> Stable Specification v1.0</div>
            <div><strong>Published:</strong> 2025-01-01</div>
            <div><strong>Editor:</strong> Joel D. Trout II, Linkism Protocol Foundation</div>
            <div><strong>License:</strong> CC BY-SA 4.0</div>
          </div>
        </div>
        
        <section>
          <h2 class="text-lg font-semibold mb-3">Abstract</h2>
          <p class="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">
            Linkism ID (LID) provides a persistent addressing scheme for UI elements that survives framework 
            migrations, redesigns, and time. This specification defines the LID URI syntax, semantics, and 
            resolution rules for creating time-invariant references to user interface components.
          </p>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">1. Introduction</h2>
          <p class="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300 mb-4">
            Modern web applications suffer from brittle element selectors that break during UI changes. LID solves this 
            by providing a standardized URI scheme for persistent element identification that:
          </p>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-4">
            <li>Decouples element references from implementation details</li>
            <li>Provides cryptographic verification of element ownership</li>
            <li>Enables air-gapped resolution workflows</li>
            <li>Survives framework migrations and redesigns</li>
          </ul>
          <p class="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">
            This RFC defines the syntax and processing rules for the lid:// URI scheme.
          </p>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">2. Terminology</h2>
          <dl class="space-y-2 text-sm">
            <div><dt class="font-semibold text-zinc-800 dark:text-zinc-200">LID:</dt> <dd class="text-zinc-700 dark:text-zinc-300">Linkism ID - persistent identifier for UI elements</dd></div>
            <div><dt class="font-semibold text-zinc-800 dark:text-zinc-200">Authority:</dt> <dd class="text-zinc-700 dark:text-zinc-300">Domain name responsible for LID registration</dd></div>
            <div><dt class="font-semibold text-zinc-800 dark:text-zinc-200">Path:</dt> <dd class="text-zinc-700 dark:text-zinc-300">Hierarchical context for element grouping</dd></div>
            <div><dt class="font-semibold text-zinc-800 dark:text-zinc-200">Fragment:</dt> <dd class="text-zinc-700 dark:text-zinc-300">Specific element identifier</dd></div>
            <div><dt class="font-semibold text-zinc-800 dark:text-zinc-200">SCR:</dt> <dd class="text-zinc-700 dark:text-zinc-300">Selector Contract Registry (RFC-002)</dd></div>
            <div><dt class="font-semibold text-zinc-800 dark:text-zinc-200">Resolver:</dt> <dd class="text-zinc-700 dark:text-zinc-300">System translating LID to current selector</dd></div>
          </dl>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">3. URI Syntax</h2>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-3">The LID URI follows this ABNF specification:</p>
          <pre class="p-3 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto mb-4 whitespace-pre-wrap">lid-URI    = "lid://" authority path [ "#" fragment ]
authority  = domain-label *( "." domain-label )
domain-label  = alphanum [ [ldh] *( alphanum | "-" ) alphanum ]
path       = [ "/" path-segment *( "/" path-segment ) ]
path-segment = *( unreserved | pct-encoded | ":" | "@" )
fragment   = *( unreserved | pct-encoded | ":" | "@" | "/" | "?" )

unreserved  = ALPHA | DIGIT | "-" | "." | "_" | "~"
pct-encoded = "%" HEXDIG HEXDIG</pre>
          
          <h3 class="text-base font-semibold mb-2">3.1 Components</h3>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li><strong>authority:</strong> DNS domain (e.g., app.com) that owns the element contract</li>
            <li><strong>path:</strong> Contextual grouping (e.g., /checkout/payment)</li>
            <li><strong>fragment:</strong> Specific element identifier (e.g., submit-button)</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">4. Character Encoding</h2>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-3">
            <li>UTF-8 encoding MUST be used throughout</li>
            <li>Domain names MUST be lowercase (IDN normalization applied)</li>
          </ul>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-2">Reserved characters MUST be percent-encoded:</p>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li># → %23</li>
            <li>/ → %2F</li>
            <li>? → %3F</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">5. Resolution Semantics</h2>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-3">Resolution follows this process:</p>
          <div class="p-3 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded text-xs text-zinc-600 dark:text-zinc-400 mb-3">
            LID URI → Parse Components → Verify Authority → Retrieve SCR Bundle → Locate Contract → Return Selector + Confidence
          </div>
          
          <h3 class="text-base font-semibold mb-2">5.1 Requirements</h3>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>Resolvers MUST implement case-sensitive matching</li>
            <li>Resolvers MUST verify SCR bundle signatures</li>
            <li>Resolvers MUST respect retirement status</li>
            <li>Resolvers MAY return confidence scores (0.0-1.0)</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">6. Immutability Guarantees</h2>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-2">Once registered, a LID MUST NOT change its:</p>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-3">
            <li>Authority</li>
            <li>Path</li>
            <li>Fragment</li>
          </ul>
          <p class="text-sm text-zinc-700 dark:text-zinc-300">
            Resolution results MAY change (selector drift). Historical contracts MUST be preserved in SCR bundles.
          </p>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">7. Lifecycle Management</h2>
          
          <h3 class="text-base font-semibold mb-2">7.1 Registration</h3>
          <pre class="p-2 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono mb-3 overflow-x-auto whitespace-pre-wrap break-all">registration = authority "::" public-key "::" timestamp</pre>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-4">
            <li>Requires proof of domain ownership</li>
            <li>Requires cryptographic signature</li>
            <li>MUST include generation timestamp</li>
          </ul>
          
          <h3 class="text-base font-semibold mb-2">7.2 Retirement</h3>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>Retired via SCR revocation list</li>
            <li>Resolution MUST return 410 (Gone) status</li>
            <li>Successor LIDs MAY be provided</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">8. Security Considerations</h2>
          
          <h3 class="text-base font-semibold mb-2">8.1 Authority Verification</h3>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-2">Resolvers MUST verify:</p>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-4">
            <li>Domain ownership during registration</li>
            <li>SCR bundle signatures during resolution</li>
          </ul>
          
          <h3 class="text-base font-semibold mb-2">8.2 Spoofing Prevention</h3>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-2">
            LIDs SHOULD include content attestations: 
            <code class="text-xs bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded break-all">lid://app.com/login#button::sha256:9f86d08...</code>
          </p>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-4">Resolvers MAY reject unsigned bundles</p>
          
          <h3 class="text-base font-semibold mb-2">8.3 Privacy</h3>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>Paths and fragments SHOULD avoid PII</li>
            <li>Bundle contents MAY be encrypted</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">9. Examples</h2>
          
          <h3 class="text-base font-semibold mb-2">9.1 Basic Identification</h3>
          <pre class="p-2 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono mb-3 overflow-x-auto whitespace-pre-wrap break-all">lid://ecommerce.com/checkout#submit-order</pre>
          
          <h3 class="text-base font-semibold mb-2">9.2 Hierarchical Context</h3>
          <pre class="p-2 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono mb-3 overflow-x-auto whitespace-pre-wrap break-all">lid://docs.app.com/sidebar/v2#search-input</pre>
          
          <h3 class="text-base font-semibold mb-2">9.3 With Content Attestation</h3>
          <pre class="p-2 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono mb-3 overflow-x-auto whitespace-pre-wrap break-all">lid://auth.service.com/login#password-field::sha256:6b86b273...</pre>
          
          <h3 class="text-base font-semibold mb-2">9.4 Resolution Workflow</h3>
          <pre class="p-3 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap"># Resolve element selector
$ linkism resolve \
    --lid lid://app.com/dashboard#metrics-chart \
    --scr ./app-v2.3.scr

→ selector: div[data-testid="metrics"] > .chart-container
→ confidence: 0.97
→ attestation: sha256:d6c7a4b...</pre>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">10. References</h2>
          <ul class="list-none space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>[RFC 3986] Uniform Resource Identifier (URI) Generic Syntax</li>
            <li>[RFC 7519] JSON Web Token (JWT)</li>
            <li>[RFC 5280] Internet X.509 Public Key Infrastructure</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">Copyright Notice</h2>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-2">
            This document is licensed under CC BY-SA 4.0. Implementations must include "LID-RFC-001" in user-agent strings.
          </p>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">Contributors</h2>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>Regolith Trust</li>
            <li>W3C Automation WG</li>
            <li>OpenJS Foundation</li>
          </ul>
          <blockquote class="mt-4 p-3 border-l-4 border-blue-500 bg-blue-50 dark:bg-blue-900/20 text-sm italic text-zinc-700 dark:text-zinc-300">
            "A web where elements outlive frameworks" — Linkism Manifesto, Section 1.1
          </blockquote>
        </section>
      </div>
    `,
  },
  "reference-impl": {
    title: "Reference Implementation · Rust Module",
    status: "stable",
    pdf: "/docs/linkism-reference-impl.pdf?v=1.0",
    html: `
      <div class="space-y-6">
        <div class="border-b border-zinc-200 dark:border-zinc-800 pb-4">
          <h1 class="text-xl font-semibold mb-2">Linkism Protocol Reference Implementation</h1>
          <div class="text-xs text-zinc-600 dark:text-zinc-400 space-y-1">
            <div><strong>Language:</strong> Rust</div>
            <div><strong>Conforms to:</strong> RFC-001, RFC-002, RFC-003</div>
            <div><strong>Author:</strong> Joel D. Trout II — Linkism Protocol Foundation</div>
            <div><strong>License:</strong> MIT</div>
          </div>
        </div>
        
        <section>
          <h2 class="text-lg font-semibold mb-3">Overview</h2>
          <p class="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300 mb-4">
            This reference implementation demonstrates core protocol capabilities with minimal dependencies. 
            The implementation focuses on readability and specification compliance rather than production optimizations.
          </p>
          <div class="p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded">
            <p class="text-sm text-amber-700 dark:text-amber-300">
              <strong>Note:</strong> Cryptographic functions are simplified for reference. 
              Production implementations MUST use proper signature verification and URI parsing per RFC-3986.
            </p>
          </div>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">Complete Implementation</h2>
          <pre class="p-4 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap">//! Reference Rust Implementation of the Linkism Protocol
//! Conforms to RFC-001, RFC-002, RFC-003
//! Author: Joel D. Trout II — Linkism Protocol Foundation
//! 
//! This implementation demonstrates core protocol capabilities:
//! - LID URI resolution (RFC-001)
//! - SCR bundle verification (RFC-002)
//! - Resolution lifecycle management (RFC-003)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------
// Core Data Structures
// ---------------------

/// LID URI representation (RFC-001 §3)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lid {
    authority: String,
    path: String,
    fragment: String,
    attestation: Option<String>,
}

impl Lid {
    /// Parse LID from URI string (RFC-001 §3.1)
    pub fn parse(uri: &str) -> Result<Self, LidError> {
        // Simplified for reference - production use RFC-3986 parser
        // Actual implementation must handle:
        // - UTF-8 encoding
        // - Percent-encoding
        // - Case normalization
        // - Authority validation
        
        if !uri.starts_with("lid://") {
            return Err(LidError::InvalidScheme);
        }
        
        let without_scheme = &uri[6..]; // Remove "lid://"
        let parts: Vec<&str> = without_scheme.split('#').collect();
        
        if parts.is_empty() {
            return Err(LidError::MissingAuthority);
        }
        
        let authority_path = parts[0];
        let fragment = parts.get(1).unwrap_or(&"").to_string();
        let attestation = parts.get(2).map(|s| s.to_string());
        
        let (authority, path) = if let Some(slash_pos) = authority_path.find('/') {
            let auth = &authority_path[..slash_pos];
            let path = &authority_path[slash_pos + 1..];
            (auth.to_string(), path.to_string())
        } else {
            (authority_path.to_string(), String::new())
        };
        
        // RFC-001 §4: Domain names MUST be lowercase
        let authority = authority.to_lowercase();
        
        if authority.is_empty() {
            return Err(LidError::MissingAuthority);
        }
        
        if fragment.is_empty() {
            return Err(LidError::MissingFragment);
        }
        
        Ok(Self {
            authority,
            path,
            fragment,
            attestation,
        })
    }
    
    /// Convert back to URI string
    pub fn to_string(&self) -> String {
        let mut uri = format!("lid://{}", self.authority);
        if !self.path.is_empty() {
            uri.push('/');
            uri.push_str(&self.path);
        }
        uri.push('#');
        uri.push_str(&self.fragment);
        if let Some(ref attestation) = self.attestation {
            uri.push_str("::");
            uri.push_str(attestation);
        }
        uri
    }
}

/// LID parsing errors
#[derive(Debug, PartialEq)]
pub enum LidError {
    InvalidScheme,
    MissingAuthority,
    MissingFragment,
    InvalidFormat,
}

/// SCR Contract (RFC-002 §4.3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    lid: String,
    selector: String,
    confidence: f32,
    attestation: Option<String>,
}

/// SCR Bundle (RFC-002 §4)
#[derive(Debug, Serialize, Deserialize)]
pub struct ScrBundle {
    #[serde(rename = "spec_version")]
    spec_version: String,
    manifest: Manifest,
    contracts: Vec<Contract>,
    revocations: Vec<Revocation>,
    signature: Signature,
    trust: Option<Trust>,
}

// ---------------------
// Bundle Substructures
// ---------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    authority: String,
    generated_at: String,  // ISO 8601 timestamp
    ttl_days: u32,
    scope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Revocation {
    lid: String,
    retired_at: String,
    successor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    algorithm: String,
    payload: String,
    chain: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Trust {
    trusted_keys: Vec<String>,
    bundle_fingerprint: String,
    generation_context: Option<String>,
    provenance: Option<String>,
}

// ---------------------
// Resolution Protocol
// ---------------------

/// Resolution result (RFC-003 §4)
#[derive(Debug, Serialize)]
pub struct ResolutionResult {
    selector: String,
    confidence: f32,
    ttl: u64,
    attestation: Option<String>,
}

/// Resolution error codes (RFC-003 §5)
#[derive(Debug, PartialEq, Clone)]
pub enum ResolutionError {
    NotFound,
    Retired(Option<String>),
    BundleExpired,
    LowConfidence,
    InvalidSignature,
    ParseError(LidError),
}

impl From<LidError> for ResolutionError {
    fn from(err: LidError) -> Self {
        ResolutionError::ParseError(err)
    }
}

impl ScrBundle {
    /// Verify bundle integrity (RFC-002 §5)
    pub fn verify(&self, public_key: &[u8]) -> Result<(), ResolutionError> {
        // 1. Verify cryptographic signature (simplified)
        // Production: Use proper cryptographic verification per RFC-002 §4.5
        if !self.verify_signature(public_key) {
            return Err(ResolutionError::InvalidSignature);
        }

        // 2. Check bundle expiration
        if self.is_expired() {
            return Err(ResolutionError::BundleExpired);
        }

        Ok(())
    }

    // Simplified for reference - production MUST use real crypto
    fn verify_signature(&self, public_key: &[u8]) -> bool {
        // Placeholder: In production, this would:
        // 1. Serialize bundle without signature field (canonical JSON)
        // 2. Compute SHA-256 hash of serialized payload
        // 3. Verify signature using public key and specified algorithm
        // 4. Validate certificate chain
        !public_key.is_empty() && !self.signature.payload.is_empty()
    }

    fn is_expired(&self) -> bool {
        // Simplified expiration check
        // Production: Parse generated_at timestamp and compare with current time
        if let Ok(generated_timestamp) = self.manifest.generated_at.parse::<u64>() {
            if let Ok(current_time) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let current_timestamp = current_time.as_secs();
                let expiry_timestamp = generated_timestamp + (self.manifest.ttl_days as u64 * 86400);
                return current_timestamp > expiry_timestamp;
            }
        }
        false
    }

    /// Resolve LID to selector (RFC-003 §2)
    pub fn resolve(&self, lid: &Lid) -> Result<ResolutionResult, ResolutionError> {
        let lid_string = lid.to_string();
        
        // 1. Check revocations first (RFC-002 §4.4)
        for revocation in &self.revocations {
            if revocation.lid == lid_string {
                return Err(ResolutionError::Retired(revocation.successor.clone()));
            }
        }

        // 2. Find matching contract (RFC-002 §4.3)
        let contract = self.contracts.iter()
            .find(|c| c.lid == lid_string)
            .ok_or(ResolutionError::NotFound)?;

        // 3. Check confidence score (RFC-003 §5.4)
        if contract.confidence < 0.7 {
            return Err(ResolutionError::LowConfidence);
        }

        // 4. Return resolution result
        Ok(ResolutionResult {
            selector: contract.selector.clone(),
            confidence: contract.confidence,
            ttl: self.manifest.ttl_days as u64 * 86400,
            attestation: contract.attestation.clone(),
        })
    }
}

// ---------------------
// API Implementation
// ---------------------

/// Handle resolution request (RFC-003 §3)
pub fn handle_resolution(
    lids: Vec<&str>,
    bundle: &ScrBundle,
    public_key: &[u8],
) -> HashMap<String, Result<ResolutionResult, ResolutionError>> {
    // Verify bundle first (RFC-003 §5.1)
    if let Err(e) = bundle.verify(public_key) {
        return lids.into_iter()
            .map(|lid| (lid.to_string(), Err(e.clone())))
            .collect();
    }

    // Resolve each LID
    lids.into_iter()
        .map(|lid_str| {
            let result = Lid::parse(lid_str)
                .map_err(ResolutionError::from)
                .and_then(|lid| bundle.resolve(&lid));
            (lid_str.to_string(), result)
        })
        .collect()
}

/// Create sample bundle for testing
pub fn create_sample_bundle() -> ScrBundle {
    ScrBundle {
        spec_version: "1.0".to_string(),
        manifest: Manifest {
            authority: "app.com".to_string(),
            generated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string(),
            ttl_days: 365,
            scope: Some("test-bundle".to_string()),
        },
        contracts: vec![
            Contract {
                lid: "lid://app.com/auth#login".to_string(),
                selector: "button.primary".to_string(),
                confidence: 0.95,
                attestation: Some("sha256:abc123...".to_string()),
            },
            Contract {
                lid: "lid://app.com/checkout#submit".to_string(),
                selector: "form.checkout button[type=submit]".to_string(),
                confidence: 0.89,
                attestation: None,
            },
        ],
        revocations: vec![
            Revocation {
                lid: "lid://app.com/old#button".to_string(),
                retired_at: "2025-01-01T00:00:00Z".to_string(),
                successor: Some("lid://app.com/new#button".to_string()),
            }
        ],
        signature: Signature {
            algorithm: "ecdsa-p256".to_string(),
            payload: "MEYCIQD5l6KjjR8H...".to_string(),
            chain: vec!["x509:org-root".to_string(), "x509:team-intermediate".to_string()],
        },
        trust: Some(Trust {
            trusted_keys: vec!["pk:ABC123...".to_string()],
            bundle_fingerprint: "sha256:d6c7a4b8...".to_string(),
            generation_context: Some("CI Build #2034".to_string()),
            provenance: Some("https://builds.app.com/2034".to_string()),
        }),
    }
}</pre>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">Test Suite</h2>
          <pre class="p-4 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap">#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_lid() {
        let lid = Lid::parse("lid://app.com/checkout#submit")
            .expect("Valid LID should parse");
        
        assert_eq!(lid.authority, "app.com");
        assert_eq!(lid.path, "checkout");
        assert_eq!(lid.fragment, "submit");
        assert_eq!(lid.attestation, None);
        
        // Test round-trip
        assert_eq!(lid.to_string(), "lid://app.com/checkout#submit");
    }

    #[test]
    fn parses_lid_with_attestation() {
        let lid = Lid::parse("lid://app.com/auth#login::sha256:abc123")
            .expect("LID with attestation should parse");
        
        assert_eq!(lid.authority, "app.com");
        assert_eq!(lid.path, "auth");
        assert_eq!(lid.fragment, "login");
        assert_eq!(lid.attestation, Some("sha256:abc123".to_string()));
    }

    #[test]
    fn handles_invalid_lids() {
        assert_eq!(Lid::parse("http://app.com/test#frag"), Err(LidError::InvalidScheme));
        assert_eq!(Lid::parse("lid://"), Err(LidError::MissingFragment));
        assert_eq!(Lid::parse("lid://app.com"), Err(LidError::MissingFragment));
    }

    #[test]
    fn resolves_valid_contract() {
        let bundle = create_sample_bundle();
        let public_key = b"test_public_key";
        
        let results = handle_resolution(
            vec!["lid://app.com/auth#login"],
            &bundle,
            public_key
        );

        let result = results.get("lid://app.com/auth#login").unwrap();
        assert!(result.is_ok());
        
        let resolution = result.as_ref().unwrap();
        assert_eq!(resolution.selector, "button.primary");
        assert_eq!(resolution.confidence, 0.95);
    }

    #[test]
    fn handles_retired_lid() {
        let bundle = create_sample_bundle();
        let public_key = b"test_public_key";
        
        let results = handle_resolution(
            vec!["lid://app.com/old#button"],
            &bundle,
            public_key
        );

        let result = results.get("lid://app.com/old#button").unwrap();
        assert!(matches!(
            result,
            Err(ResolutionError::Retired(Some(successor))) if successor == "lid://app.com/new#button"
        ));
    }

    #[test]
    fn handles_not_found() {
        let bundle = create_sample_bundle();
        let public_key = b"test_public_key";
        
        let results = handle_resolution(
            vec!["lid://app.com/nonexistent#element"],
            &bundle,
            public_key
        );

        let result = results.get("lid://app.com/nonexistent#element").unwrap();
        assert!(matches!(result, Err(ResolutionError::NotFound)));
    }

    #[test]
    fn handles_low_confidence() {
        let mut bundle = create_sample_bundle();
        bundle.contracts[1].confidence = 0.5; // Below 0.7 threshold
        let public_key = b"test_public_key";
        
        let results = handle_resolution(
            vec!["lid://app.com/checkout#submit"],
            &bundle,
            public_key
        );

        let result = results.get("lid://app.com/checkout#submit").unwrap();
        assert!(matches!(result, Err(ResolutionError::LowConfidence)));
    }

    #[test]
    fn handles_bundle_verification_failure() {
        let bundle = create_sample_bundle();
        let empty_key = b""; // Invalid key
        
        let results = handle_resolution(
            vec!["lid://app.com/auth#login"],
            &bundle,
            empty_key
        );

        let result = results.get("lid://app.com/auth#login").unwrap();
        assert!(matches!(result, Err(ResolutionError::InvalidSignature)));
    }
}</pre>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">Usage Examples</h2>
          
          <h3 class="text-base font-semibold mb-2">Basic Resolution</h3>
          <pre class="p-3 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap">use linkism_protocol::{Lid, ScrBundle, handle_resolution, create_sample_bundle};

fn main() {
    // Load or create SCR bundle
    let bundle = create_sample_bundle();
    let public_key = b"your_public_key_here";
    
    // Resolve multiple LIDs
    let results = handle_resolution(
        vec![
            "lid://app.com/auth#login",
            "lid://app.com/checkout#submit"
        ],
        &bundle,
        public_key
    );
    
    // Process results
    for (lid, result) in results {
        match result {
            Ok(resolution) => {
                println!("LID: {}", lid);
                println!("Selector: {}", resolution.selector);
                println!("Confidence: {}", resolution.confidence);
                println!("TTL: {} seconds", resolution.ttl);
                if let Some(attestation) = resolution.attestation {
                    println!("Attestation: {}", attestation);
                }
                println!("---");
            }
            Err(error) => {
                eprintln!("Failed to resolve {}: {:?}", lid, error);
            }
        }
    }
}</pre>

          <h3 class="text-base font-semibold mb-2">CLI Tool Example</h3>
          <pre class="p-3 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap">// Example CLI tool using the reference implementation
use clap::{App, Arg};
use std::fs;

fn main() {
    let matches = App::new("linkism-resolve")
        .version("1.0")
        .about("Resolves LIDs using SCR bundles")
        .arg(Arg::with_name("lid")
            .long("lid")
            .value_name("LID")
            .help("LID to resolve")
            .required(true))
        .arg(Arg::with_name("scr")
            .long("scr")
            .value_name("BUNDLE")
            .help("Path to SCR bundle file")
            .required(true))
        .get_matches();

    let lid_str = matches.value_of("lid").unwrap();
    let bundle_path = matches.value_of("scr").unwrap();
    
    // Load bundle from file
    let bundle_json = fs::read_to_string(bundle_path)
        .expect("Failed to read SCR bundle");
    let bundle: ScrBundle = serde_json::from_str(&bundle_json)
        .expect("Failed to parse SCR bundle");
    
    // Resolve LID
    let public_key = b"your_key"; // Load from config
    let results = handle_resolution(vec![lid_str], &bundle, public_key);
    
    match results.get(lid_str).unwrap() {
        Ok(resolution) => {
            println!("→ selector: {}", resolution.selector);
            println!("→ confidence: {}", resolution.confidence);
            println!("→ ttl: {} seconds", resolution.ttl);
        }
        Err(error) => {
            eprintln!("Resolution failed: {:?}", error);
            std::process::exit(1);
        }
    }
}</pre>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">Production Considerations</h2>
          <div class="space-y-4">
            <div class="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded">
              <h4 class="font-semibold text-red-800 dark:text-red-400 mb-2">🚨 Security Requirements</h4>
              <ul class="list-disc pl-6 space-y-1 text-sm text-red-700 dark:text-red-300">
                <li>Replace placeholder crypto with proper ECDSA/RSA signature verification</li>
                <li>Use established cryptographic libraries (ring, rustls, etc.)</li>
                <li>Implement proper certificate chain validation</li>
                <li>Add timing attack protections for signature verification</li>
              </ul>
            </div>
            
            <div class="p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded">
              <h4 class="font-semibold text-blue-800 dark:text-blue-400 mb-2">📐 Standards Compliance</h4>
              <ul class="list-disc pl-6 space-y-1 text-sm text-blue-700 dark:text-blue-300">
                <li>Implement full RFC-3986 URI parsing and validation</li>
                <li>Add proper IDN (International Domain Name) support</li>
                <li>Handle all percent-encoding edge cases</li>
                <li>Validate authority ownership via DNS TXT records</li>
              </ul>
            </div>
            
            <div class="p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded">
              <h4 class="font-semibold text-green-800 dark:text-green-400 mb-2">⚡ Performance & Reliability</h4>
              <ul class="list-disc pl-6 space-y-1 text-sm text-green-700 dark:text-green-300">
                <li>Add caching layer for resolved selectors with TTL respect</li>
                <li>Implement bundle streaming for large SCR files</li>
                <li>Add metrics and observability hooks</li>
                <li>Handle network failures gracefully with retries</li>
              </ul>
            </div>
          </div>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">Adoption Pathways</h2>
          
          <h3 class="text-base font-semibold mb-2">Progressive Integration</h3>
          <div class="p-4 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded mb-4">
            <h4 class="font-semibold mb-2">LID-First Migration Strategy</h4>
            <pre class="text-xs font-mono whitespace-pre-wrap mb-2">// Add LID comments to existing tests
cy.get('button.primary')
  .should('be.visible')
  .comment('lid://app.com/auth#login');</pre>
            <p class="text-sm text-zinc-700 dark:text-zinc-300">
              Tools can automatically generate SCR bundles from these comments during test runs.
            </p>
          </div>

          <h3 class="text-base font-semibold mb-2">Hosted SCR Registry</h3>
          <div class="p-4 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded">
            <pre class="text-xs font-mono whitespace-pre-wrap"># Auto-update SCR bundles
linkism sync --auto-update --ttl=30d

# Cloud-based signing with KMS
linkism bundle --kms aws:alias/linkism-prod</pre>
          </div>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">Integration Examples</h2>
          
          <h3 class="text-base font-semibold mb-2">Test Framework Integration</h3>
          <div class="space-y-3">
            <div class="p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded">
              <h4 class="font-semibold text-blue-800 dark:text-blue-400 mb-2">Cypress Example</h4>
              <pre class="text-xs font-mono overflow-x-auto whitespace-pre-wrap">// cypress/support/commands.js
Cypress.Commands.add('getLID', (lid) => {
  return cy.window().then((win) => {
    return win.linkismResolve(lid).then(result => {
      return cy.get(result.selector, { timeout: result.ttl * 1000 });
    });
  });
});

// Usage in tests
cy.getLID('lid://app.com/auth#login').click();</pre>
            </div>
            
            <div class="p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded">
              <h4 class="font-semibold text-green-800 dark:text-green-400 mb-2">Playwright Example</h4>
              <pre class="text-xs font-mono overflow-x-auto whitespace-pre-wrap">// playwright.config.js
export default {
  use: {
    // Auto-resolve LIDs to selectors
    lidResolver: 'https://api.linkism.org/v1'
  }
};

// Usage in tests
await page.lid('lid://app.com/checkout#submit').click();</pre>
            </div>
          </div>
        </section>
      </div>
    `,
  },
  "rfc-002": {
    title: "RFC-002 · SCR Bundle Format",
    status: "stable", 
    pdf: "/docs/lid-rfc-002.pdf",
    html: `
      <div class="space-y-6">
        <div class="border-b border-zinc-200 dark:border-zinc-800 pb-4">
          <h1 class="text-xl font-semibold mb-2">LID-RFC-002: SCR Bundle Specification</h1>
          <div class="text-xs text-zinc-600 dark:text-zinc-400 space-y-1">
            <div><strong>Category:</strong> Standards Track</div>
            <div><strong>Version:</strong> 1.0</div>
            <div><strong>Editor:</strong> Joel David Trout II</div>
            <div><strong>License:</strong> CC BY-SA 4.0</div>
            <div><strong>Last Updated:</strong> August 2025</div>
          </div>
        </div>
        
        <section>
          <h2 class="text-lg font-semibold mb-3">Abstract</h2>
          <p class="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">
            The Selector Contract Registry (SCR) Bundle defines a cryptographically signed, portable contract format 
            for mapping Linkism IDs (LIDs) to implementation selectors. This enables stable, verifiable resolution 
            of UI elements independent of DOM drift, supporting air-gapped environments, time-travel debugging, 
            and cross-team UI integrity contracts.
          </p>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">1. Introduction</h2>
          <p class="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300 mb-4">
            UI automation often fails due to fragile selectors tightly coupled to dynamic DOM structures. 
            LID-RFC-001 introduced immutable element addresses (lid://...) as persistent identifiers.
          </p>
          <p class="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300 mb-3">
            This document defines the corresponding registry format: SCR bundles. These bundles contain:
          </p>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-4">
            <li>LID-to-selector contracts</li>
            <li>Content attestations</li>
            <li>Cryptographic signatures</li>
            <li>Optional successor relationships for retired LIDs</li>
          </ul>
          <p class="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">
            SCR bundles enable both online and offline resolution workflows and serve as audit artifacts 
            for UI compliance, test stability, and change forensics.
          </p>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">2. Terminology</h2>
          <div class="overflow-x-auto">
            <table class="w-full text-sm border border-zinc-200 dark:border-zinc-800 rounded">
              <thead class="bg-zinc-50 dark:bg-zinc-900">
                <tr>
                  <th class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 text-left font-semibold">Term</th>
                  <th class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 text-left font-semibold">Definition</th>
                </tr>
              </thead>
              <tbody class="text-xs">
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono">SCR</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Selector Contract Registry — bundle format for LID contracts</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono">Contract</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">LID → selector mapping</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono">Attestation</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Optional cryptographic hash of element content</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono">Revocation</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Declaration of retired LIDs with optional successors</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono">Trust Chain</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Signature and certificate metadata for validating bundles</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">3. Bundle Structure</h2>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-3">An SCR bundle is a signed JSON document with the following schema:</p>
          <pre class="p-4 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap">{
  "spec_version": "1.0",        // §4.1: Protocol version
  "manifest": {                 // §4.2: Bundle metadata
    "authority": "app.com",
    "generated_at": "2025-01-01T00:00:00Z",
    "ttl_days": 365
  },
  "contracts": [                // §4.3: Active LID mappings
    {
      "lid": "lid://app.com/auth#login",
      "selector": "form#login > button.primary",
      "confidence": 1.0,
      "attestation": "sha256:9f86d08..."
    }
  ],
  "revocations": ["lid://app.com/legacy#submit"],  // §4.4: Retired LIDs
  "signature": {                // §4.5: Cryptographic verification
    "algorithm": "ecdsa-p256",
    "payload": "MEYCI...",
    "chain": ["x509:org-root", "x509:team-issued"]
  },
  "trust": {                    // §4.6: Trust anchors
    "trusted_keys": ["pk:..."],
    "bundle_fingerprint": "sha256:d6c7a4...",
    "generation_context": "CI Build #2034",
    "provenance": "https://builds.app.com/2034"
  }
}</pre>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">4. Required Fields</h2>
          
          <h3 class="text-base font-semibold mb-2">4.1 manifest</h3>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-4">
            <li><strong>authority</strong> — domain that owns this bundle (must match LID authority)</li>
            <li><strong>generated_at</strong> — ISO 8601 UTC timestamp</li>
            <li><strong>ttl_days</strong> — time-to-live in days (after which bundle is expired)</li>
            <li><strong>scope</strong> — optional label for organizational grouping (e.g., "design-system")</li>
          </ul>

          <h3 class="text-base font-semibold mb-2">4.2 contracts</h3>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-2">Each contract MUST include:</p>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-4">
            <li><strong>lid</strong> — immutable LID address</li>
            <li><strong>selector</strong> — current valid CSS selector for the element</li>
            <li><strong>confidence</strong> — float between 0.0 and 1.0</li>
            <li><strong>attestation</strong> — optional sha256 hash of element content</li>
          </ul>

          <h3 class="text-base font-semibold mb-2">4.3 revocations</h3>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-2">Used for deprecating LIDs. Each entry includes:</p>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-4">
            <li><strong>lid</strong> — retired LID</li>
            <li><strong>retired_at</strong> — timestamp of removal</li>
            <li><strong>successor</strong> — optional replacement LID</li>
          </ul>

          <h3 class="text-base font-semibold mb-2">4.4 signature</h3>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-2">
            Cryptographic signature of the bundle contents, using canonical JSON serialization. Includes:
          </p>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-4">
            <li><strong>algorithm</strong> — e.g., ecdsa-p256 or rsa-pss-2048</li>
            <li><strong>payload</strong> — base64-encoded signature of the bundle sans signature block</li>
            <li><strong>chain</strong> — certificate chain for trust verification</li>
          </ul>

          <h3 class="text-base font-semibold mb-2">4.5 trust</h3>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-2">
            Optional metadata to assist in bundle tracking and provenance. Fields include:
          </p>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li><strong>trusted_keys</strong> — public keys used to verify the chain</li>
            <li><strong>bundle_fingerprint</strong> — SHA-256 hash of full serialized bundle</li>
            <li><strong>generation_context</strong> — build environment descriptor</li>
            <li><strong>provenance</strong> — URL or system of origin</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">5. Verification Rules</h2>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-3">Resolvers MUST:</p>
          
          <div class="space-y-4">
            <div class="p-3 border border-zinc-200 dark:border-zinc-800 rounded">
              <h4 class="font-semibold text-sm text-zinc-800 dark:text-zinc-200 mb-2">1. Verify Signature</h4>
              <ul class="list-disc pl-4 space-y-1 text-xs text-zinc-700 dark:text-zinc-300">
                <li>Validate chain against known roots</li>
                <li>Reject untrusted or expired chains</li>
              </ul>
            </div>

            <div class="p-3 border border-zinc-200 dark:border-zinc-800 rounded">
              <h4 class="font-semibold text-sm text-zinc-800 dark:text-zinc-200 mb-2">2. Check TTL</h4>
              <p class="text-xs text-zinc-700 dark:text-zinc-300">Reject if generated_at + ttl_days is in the past</p>
            </div>

            <div class="p-3 border border-zinc-200 dark:border-zinc-800 rounded">
              <h4 class="font-semibold text-sm text-zinc-800 dark:text-zinc-200 mb-2">3. Honor Revocations</h4>
              <ul class="list-disc pl-4 space-y-1 text-xs text-zinc-700 dark:text-zinc-300">
                <li>Retired LIDs MUST return 410 Gone</li>
                <li>Use successor if provided</li>
              </ul>
            </div>

            <div class="p-3 border border-zinc-200 dark:border-zinc-800 rounded">
              <h4 class="font-semibold text-sm text-zinc-800 dark:text-zinc-200 mb-2">4. Check Confidence</h4>
              <p class="text-xs text-zinc-700 dark:text-zinc-300">Resolution MAY be rejected if confidence < threshold</p>
            </div>

            <div class="p-3 border border-zinc-200 dark:border-zinc-800 rounded">
              <h4 class="font-semibold text-sm text-zinc-800 dark:text-zinc-200 mb-2">5. Verify Attestation</h4>
              <ul class="list-disc pl-4 space-y-1 text-xs text-zinc-700 dark:text-zinc-300">
                <li>Optional but strongly RECOMMENDED</li>
                <li>If present, verify DOM hash matches attestation</li>
              </ul>
            </div>
          </div>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">6. Resolution Lifecycle</h2>
          <div class="overflow-x-auto">
            <table class="w-full text-sm border border-zinc-200 dark:border-zinc-800 rounded">
              <thead class="bg-zinc-50 dark:bg-zinc-900">
                <tr>
                  <th class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 text-left font-semibold">Action</th>
                  <th class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 text-left font-semibold">Protocol Behavior</th>
                  <th class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 text-left font-semibold">Error Code</th>
                </tr>
              </thead>
              <tbody class="text-xs">
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Valid resolve</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Return selector, metadata</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono text-green-600 dark:text-green-400">200</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Retired LID</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Return successor or 410</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono text-yellow-600 dark:text-yellow-400">410</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Unknown LID</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">No match in bundle</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono text-red-600 dark:text-red-400">404</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Expired TTL</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Bundle considered stale</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono text-orange-600 dark:text-orange-400">423</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Low confidence</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Optional client rejection</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono text-blue-600 dark:text-blue-400">412</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">7. Examples</h2>
          
          <h3 class="text-base font-semibold mb-2">7.1 Basic Contract</h3>
          <pre class="p-3 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap">{
  "lid": "lid://shop.com/cart#checkout",
  "selector": "button[data-testid='checkout']",
  "confidence": 0.96
}</pre>

          <h3 class="text-base font-semibold mb-2 mt-4">7.2 Revocation Entry</h3>
          <pre class="p-3 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap">{
  "lid": "lid://shop.com/cart#legacy-button",
  "retired_at": "2025-02-10T00:00:00Z",
  "successor": "lid://shop.com/cart#checkout"
}</pre>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">8. Security Considerations</h2>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li><strong>Replay Prevention:</strong> TTL and fingerprints reduce bundle misuse</li>
            <li><strong>Spoofing Protection:</strong> Attestations ensure element integrity</li>
            <li><strong>Key Rotation:</strong> Follow BCP-LID-001 §4 for revocation and refresh</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">9. References</h2>
          <ul class="list-none space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>[LID-RFC-001] — Linkism URI Scheme</li>
            <li>[RFC7515] — JSON Web Signature (JWS)</li>
            <li>[BCP-LID-001] — Deployment Guidelines for LID Infrastructure</li>
          </ul>
        </section>
      </div>
    `,
  },
  "rfc-003": {
    title: "RFC-003 · Resolution Protocol",
    status: "draft",
    pdf: "/docs/lid-rfc-003.pdf", 
    html: `
      <div class="space-y-6">
        <div class="border-b border-zinc-200 dark:border-zinc-800 pb-4">
          <h1 class="text-xl font-semibold mb-2">LID-RFC-003: Resolution Protocol</h1>
          <div class="text-xs text-zinc-600 dark:text-zinc-400 space-y-1">
            <div><strong>Title:</strong> LID Resolution Protocol</div>
            <div><strong>Version:</strong> 1.0</div>
            <div><strong>Status:</strong> Draft</div>
            <div><strong>Category:</strong> Standards Track</div>
            <div><strong>Editor:</strong> Linkism Protocol Foundation</div>
            <div><strong>Last Updated:</strong> August 2025</div>
          </div>
        </div>
        
        <section>
          <h2 class="text-lg font-semibold mb-3">Abstract</h2>
          <p class="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">
            This document defines the Linkism Resolution Protocol, a standardized mechanism for resolving 
            LID (Linkism ID) URIs into current, context-aware CSS selectors. The protocol enables integration 
            with test runners, RPA engines, and AI agents while preserving immutability and cryptographic 
            integrity via SCR (Selector Contract Registry) bundles.
          </p>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">1. Introduction</h2>
          <p class="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">
            LIDs are persistent identifiers for UI elements that decouple logical element contracts from 
            implementation-specific selectors. The Resolution Protocol provides the interface and expectations 
            for translating LIDs into selectors in real time, offline or networked, with cryptographic guarantees.
          </p>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">2. Goals</h2>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>Provide a simple, extensible API for resolving LIDs</li>
            <li>Support air-gapped (offline) and network-based workflows</li>
            <li>Enforce integrity via bundle fingerprinting and signature checks</li>
            <li>Return metadata including confidence scores, TTLs, and errors</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">3. Resolution Request</h2>
          <div class="mb-3">
            <div class="text-sm font-semibold text-zinc-800 dark:text-zinc-200 mb-2">Endpoint Details:</div>
            <ul class="list-none space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-4">
              <li><strong>Endpoint:</strong> <code class="text-xs bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">/v1/resolve-many</code></li>
              <li><strong>Method:</strong> <code class="text-xs bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">POST</code></li>
              <li><strong>Content-Type:</strong> <code class="text-xs bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">application/json</code></li>
            </ul>
          </div>

          <h3 class="text-base font-semibold mb-2">Request Schema</h3>
          <pre class="p-3 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap mb-4">{
  "lids": [
    "lid://app.com/checkout#submit",
    "lid://auth.app.com/login#continue"
  ],
  "bundle_fingerprint": "sha256:d6c7a4...",
  "options": {
    "strict": true,
    "fallback": false
  }
}</pre>

          <h3 class="text-base font-semibold mb-2">Field Definitions</h3>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li><strong>lids:</strong> Array of valid LID URIs</li>
            <li><strong>bundle_fingerprint:</strong> Optional SHA-256 hash of known SCR bundle</li>
            <li><strong>options.strict:</strong> Require attestation + full trust chain (default: false)</li>
            <li><strong>options.fallback:</strong> Allow non-bundle fallback (default: false)</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">4. Resolution Response</h2>
          <div class="mb-3">
            <div class="text-sm font-semibold text-zinc-800 dark:text-zinc-200">Status: <span class="text-green-600 dark:text-green-400">200 OK</span></div>
          </div>

          <h3 class="text-base font-semibold mb-2">Response Schema</h3>
          <pre class="p-3 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap mb-4">{
  "lid://app.com/checkout#submit": {
    "selector": "button.checkout-final",
    "confidence": 0.95,
    "ttl": 43200,
    "attestation": "sha256:6b86b273..."
  },
  "lid://auth.app.com/login#continue": {
    "selector": "form#login .btn-continue",
    "confidence": 1.0,
    "ttl": 86400
  }
}</pre>

          <h3 class="text-base font-semibold mb-2">Response Fields</h3>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li><strong>selector:</strong> Current selector (valid in UI context)</li>
            <li><strong>confidence:</strong> Float between 0.0–1.0</li>
            <li><strong>ttl:</strong> Time in seconds the selector remains trusted</li>
            <li><strong>attestation:</strong> Optional hash for content validation</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-">5. Error Semantics</h2>
          <div class="overflow-x-auto">
            <table class="w-full text-sm border border-zinc-200 dark:border-zinc-800 rounded">
              <thead class="bg-zinc-50 dark:bg-zinc-900">
                <tr>
                  <th class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 text-left font-semibold">Status Code</th>
                  <th class="border border-zinc-200 dark:border-800 px-3 py-2 text-left font-semibold">Meaning</th>
                </tr>
              </thead>
              <tbody class="text-xs">
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono text-red-600 dark:text-red-400">404</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">LID not found in SCR bundle</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono text-yellow-600 dark:text-yellow-400">410</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">LID explicitly retired</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono text-orange-600 dark:text-orange-400">423</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Bundle expired (TTL exceeded)</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono text-purple-600 dark:text-purple-400">498</d>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Invalid signature or fingerprint</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 font-mono text-blue-600 dark:text-blue-400">409</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Conflicting LIDs from multiple SCR</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">6. Local vs Remote Resolution</h2>
          
          <h3 class="text-base font-semibold mb-2">6.1 Local (Air-Gapped)</h3>
          <pre class="p-3 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap mb-3">linkism resolve \\
  --lid lid://app.com/auth#login \\
  --scr ./auth.scr</pre>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-4">
            <li>No network required</li>
            <li>Reads local bundle</li>
            <li>Fails on signature or expiry</li>
          </ul>

          <h3 class="text-base font-semibold mb-2">6.2 Remote (Resolver API)</h3>
          <pre class="p-3 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap mb-3">POST /v1/resolve-many
Host: api.linkism.org
Authorization: Bearer &lt;token&gt;</pre>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>Handles SCR lookup</li>
            <li>Caches bundle fingerprint</li>
            <li>Optionally verifies remote attestation</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">7. Security Considerations</h2>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>All responses MUST be derived from verified SCR bundles</li>
            <li>If <code class="text-xs bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">strict</code> is true, LIDs MUST be signed and attested</li>
            <li>Bundle expiry MUST enforce 423 Locked if TTL is violated</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">8. Compatibility</h2>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>Compatible with all SCR bundle versions >= 1.0</li>
            <li>Implementations MAY cache successful resolutions per TTL</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">9. Example CLI Workflow</h2>
          <pre class="p-4 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap"># Step 1: Bundle selectors
linkism bundle \\
  --lid lid://app.com/auth#login \\
  --selector 'form#login > button.primary' \\
  --key ./team-key.pem \\
  --output auth.scr

# Step 2: Resolve
linkism resolve \\
  --lid lid://app.com/auth#login \\
  --scr ./auth.scr

# Output:
# → selector: form#login > button.primary
# → confidence: 1.0
# → attestation: sha256:...</pre>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">10. References</h2>
          <ul class="list-none space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>[RFC-001] LID URI Syntax</li>
            <li>[RFC-002] SCR Bundle Format</li>
            <li>[BCP-LID-001] Best Practices for LID Deployment</li>
            <li>[RFC 7519] JSON Web Token (JWT)</li>
            <li>[RFC 3986] URI Generic Syntax</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">License</h2>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-2">
            CC BY-SA 4.0
          </p>
          <p class="text-sm text-zinc-700 dark:text-zinc-300">
            All protocol implementations must acknowledge this RFC in their API documentation and response headers 
            (e.g., <code class="text-xs bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">X-Linkism-RFC: 003</code>).
          </p>
        </section>
      </div>
    `,
  },
  "bcp-001": {
    title: "BCP-001 · Deployment Guidelines", 
    status: "stable",
    pdf: "/docs/bcp-lid-001.pdf",
    html: `
      <div class="space-y-6">
        <div class="border-b border-zinc-200 dark:border-zinc-800 pb-4">
          <h1 class="text-xl font-semibold mb-2">BCP-LID-001: Linkism ID Deployment Guidelines</h1>
          <p class="text-sm italic text-zinc-600 dark:text-zinc-400 mb-3">"Operational Wisdom for Persistent Element Identifiers"</p>
          <div class="text-xs text-zinc-600 dark:text-zinc-400 space-y-1">
            <div><strong>Category:</strong> Informational</div>
            <div><strong>Updates:</strong> LID-RFC-001</div>
            <div><strong>Published:</strong> 2025-03-01</div>
            <div><strong>Editor:</strong> Linkism Protocol Foundation</div>
          </div>
        </div>

        <section>
          <h2 class="text-lg font-semibold mb-3">1. Introduction</h2>
          <p class="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300 mb-3">
            This document provides deployment guidelines, anti-patterns, and namespace strategies for LID implementations. It answers:
          </p>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>How should teams structure LIDs?</li>
            <li>What makes a LID resilient?</li>
            <li>How to avoid common pitfalls?</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">2. LID Naming Conventions</h2>
          
          <h3 class="text-base font-semibold mb-2">2.1 Authority Selection</h3>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div class="p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded">
              <h4 class="font-semibold text-green-800 dark:text-green-400 mb-2">✅ Do:</h4>
              <ul class="list-disc pl-4 space-y-1 text-sm text-green-700 dark:text-green-300">
                <li>Use domains you control long-term (<code class="text-xs bg-green-100 dark:bg-green-900/30 px-1 py-0.5 rounded">lid://company.com</code>)</li>
                <li>Prefer subdomains for teams (<code class="text-xs bg-green-100 dark:bg-green-900/30 px-1 py-0.5 rounded">lid://team.company.com</code>)</li>
              </ul>
            </div>
            <div class="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded">
              <h4 class="font-semibold text-red-800 dark:text-red-400 mb-2">❌ Avoid:</h4>
              <ul class="list-disc pl-4 space-y-1 text-sm text-red-700 dark:text-red-300">
                <li>Ephemeral domains (<code class="text-xs bg-red-100 dark:bg-red-900/30 px-1 py-0.5 rounded">lid://staging-env-38.com</code>)</li>
                <li>IP addresses (<code class="text-xs bg-red-100 dark:bg-red-900/30 px-1 py-0.5 rounded">lid://192.168.1.1</code>)</li>
              </ul>
            </div>
          </div>

          <h3 class="text-base font-semibold mb-2">2.2 Path Design</h3>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div class="p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded">
              <h4 class="font-semibold text-green-800 dark:text-green-400 mb-2">✅ Do:</h4>
              <p class="text-sm text-green-700 dark:text-green-300 mb-2">Mirror URL structure:</p>
              <pre class="text-xs font-mono bg-green-100 dark:bg-green-900/30 p-2 rounded overflow-x-auto whitespace-pre-wrap break-all">lid://app.com/checkout/payment#submit
lid://docs.com/api/v2#search-input</pre>
              <p class="text-sm text-green-700 dark:text-green-300 mt-2 mb-1">Use @ for owned namespaces:</p>
              <pre class="text-xs font-mono bg-green-100 dark:bg-green-900/30 p-2 rounded overflow-x-auto whitespace-pre-wrap break-all">lid://app.com/@design-system/button#primary</pre>
            </div>
            <div class="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded">
              <h4 class="font-semibold text-red-800 dark:text-red-400 mb-2">❌ Avoid:</h4>
              <ul class="list-disc pl-4 space-y-1 text-sm text-red-700 dark:text-red-300">
                <li>Over-nesting (/page/section/component/subcomponent)</li>
                <li>Unversioned paths (/api vs. /api/v2)</li>
              </ul>
            </div>
          </div>

          <h3 class="text-base font-semibold mb-2">2.3 Fragment Semantics</h3>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded">
              <h4 class="font-semibold text-green-800 dark:text-green-400 mb-2">✅ Do:</h4>
              <ul class="list-disc pl-4 space-y-1 text-sm text-green-700 dark:text-green-300">
                <li>Be specific but concise (#submit-order, not #btn)</li>
                <li>Include element type (#search-input, #avatar-image)</li>
              </ul>
            </div>
            <div class="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded">
              <h4 class="font-semibold text-red-800 dark:text-red-400 mb-2">❌ Avoid:</h4>
              <ul class="list-disc pl-4 space-y-1 text-sm text-red-700 dark:text-red-300">
                <li>PII (#user-email)</li>
                <li>Transient states (#expanded)</li>
              </ul>
            </div>
          </div>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">3. SCR Bundle Hygiene</h2>
          
          <h3 class="text-base font-semibold mb-2">3.1 Bundle Segmentation</h3>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-3">
            <li><strong>Small Apps:</strong> Single bundle</li>
            <li><strong>Large Apps:</strong> Split by team/domain</li>
          </ul>
          <pre class="p-3 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap">// scr-team-auth.json
{ "scope": "lid://app.com/@auth/*" }</pre>

          <h3 class="text-base font-semibold mb-2 mt-4">3.2 TTL Policies</h3>
          <div class="overflow-x-auto">
            <table class="w-full text-sm border border-zinc-200 dark:border-zinc-800 rounded">
              <thead class="bg-zinc-50 dark:bg-zinc-900">
                <tr>
                  <th class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 text-left">Bundle Type</th>
                  <th class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 text-left">Recommended TTL</th>
                </tr>
              </thead>
              <tbody class="text-xs">
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Design Systems</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">365 days</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Checkout Flows</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">90 days</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">A/B Test Variants</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">30 days</td>
                </tr>
              </tbody>
            </table>
          </div>

          <h3 class="text-base font-semibold mb-2 mt-4">3.3 Revocation Strategy</h3>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-2">Retire LIDs before removing elements. Always declare successors:</p>
          <pre class="p-3 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap">{
  "retired": "lid://app.com/old#btn",
  "successor": "lid://app.com/new#button"
}</pre>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">4. Security & Privacy</h2>
          
          <h3 class="text-base font-semibold mb-2">4.1 Attestation Practices</h3>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300 mb-2">
            <li><strong>Critical Elements:</strong> Always hash content</li>
            <li><strong>Non-Critical:</strong> Skip hashing for performance</li>
          </ul>
          <pre class="p-2 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all">lid://bank.com/transfer#amount::sha256:6b86b2...</pre>

          <h3 class="text-base font-semibold mb-2 mt-4">4.2 Key Rotation</h3>
          <ol class="list-decimal pl-6 space-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>Generate new keys annually</li>
            <li>Publish old keys in <code class="text-xs bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">_linkism-revoked</code> DNS TXT</li>
          </ol>

          <h3 class="text-base font-semibold mb-2 mt-4">4.3 PII Mitigation</h3>
          <div class="space-y-3">
            <div class="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded">
              <p class="text-sm font-semibold text-red-800 dark:text-red-400 mb-1">🚨 Problem:</p>
              <pre class="text-xs font-mono bg-red-100 dark:bg-red-900/30 p-2 rounded overflow-x-auto whitespace-pre-wrap break-all">lid://clinic.com/patients#name  // Bad</pre>
            </div>
            <div class="p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded">
              <p class="text-sm font-semibold text-green-800 dark:text-green-400 mb-1">✅ Solution:</p>
              <pre class="text-xs font-mono bg-green-100 dark:bg-green-900/30 p-2 rounded overflow-x-auto whitespace-pre-wrap break-all">lid://clinic.com/records#patient-detail::sha256:...  // Hashed</pre>
            </div>
          </div>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">5. Conflict Avoidance</h2>
          
          <h3 class="text-base font-semibold mb-2">5.1 Team Namespacing</h3>
          <div class="overflow-x-auto">
            <table class="w-full text-sm border border-zinc-200 dark:border-zinc-800 rounded">
              <thead class="bg-zinc-50 dark:bg-zinc-900">
                <tr>
                  <th class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 text-left">Model</th>
                  <th class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 text-left">Example</th>
                  <th class="border border-zinc-200 dark:border-zinc-800 px-3 py-2 text-left">Use Case</th>
                </tr>
              </thead>
              <tbody class="text-xs">
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Subdomain</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2"><code class="bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">lid://team.app.com</code></td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Independent products</td>
                </tr>
                <tr>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Path Prefix</td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2"><code class="bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">lid://app.com/@team</code></td>
                  <td class="border border-zinc-200 dark:border-zinc-800 px-3 py-2">Monorepos</td>
                </tr>
              </tbody>
            </table>
          </div>

          <h3 class="text-base font-semibold mb-2 mt-4">5.2 Merge Policies</h3>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li><strong>Allow:</strong> Bundles with disjoint LID sets</li>
            <li><strong>Reject:</strong> Bundles with overlapping LIDs (throw 409)</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">6. Debugging LIDs</h2>
          
          <h3 class="text-base font-semibold mb-2">6.1 Forensic Tools</h3>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-2">LID Explorer:</p>
          <pre class="p-3 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap">linkism audit --lid lid://app.com/modal#close --scr ./bundles/*

Outputs:
History:
2024-01-01 - selector: ".modal-close" (confidence: 0.99)
2024-06-01 - selector: "[data-testid=close-btn]" (confidence: 0.95)</pre>

          <h3 class="text-base font-semibold mb-2 mt-4">6.2 Breakage Triaging</h3>
          <ol class="list-decimal pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li>Check confidence scores</li>
            <li>Compare attestation hashes</li>
            <li>Verify bundle expiration</li>
          </ol>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">7. Examples</h2>
          
          <h3 class="text-base font-semibold mb-2">7.1 Good LIDs</h3>
          <div class="space-y-1">
            <pre class="p-2 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all">lid://shop.com/checkout#apply-promo</pre>
            <pre class="p-2 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all">lid://design.acme.com/@ds3/button#primary</pre>
            <pre class="p-2 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all">lid://gov.uk/tax-form#error-ssn::sha256:...</pre>
          </div>

          <h3 class="text-base font-semibold mb-2 mt-4">7.2 LIDs to Avoid</h3>
          <div class="space-y-2">
            <div class="p-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded">
              <pre class="text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all">lid://temp.com/modal#close</pre>
              <p class="text-xs text-red-700 dark:text-red-300 mt-1">// Ephemeral authority</p>
            </div>
            <div class="p-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded">
              <pre class="text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all">lid://app.com/#main-button</pre>
              <p class="text-xs text-red-700 dark:text-red-300 mt-1">// No path context</p>
            </div>
            <div class="p-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded">
              <pre class="text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all">lid://health.com/patients#diabetes</pre>
              <p class="text-xs text-red-700 dark:text-red-300 mt-1">// PII in fragment</p>
            </div>
          </div>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">Appendix A: Adoption Checklist</h2>
          <ul class="space-y-1 text-sm">
            <li class="flex items-center gap-2">
              <input type="checkbox" class="rounded" />
              <span class="text-zinc-700 dark:text-zinc-300">Register <code class="text-xs bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">_linkism</code> DNS TXT records</span>
            </li>
            <li class="flex items-center gap-2">
              <input type="checkbox" class="rounded" />
              <span class="text-zinc-700 dark:text-zinc-300">Run <code class="text-xs bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">linkism lint</code> to validate naming</span>
            </li>
            <li class="flex items-center gap-2">
              <input type="checkbox" class="rounded" />
              <span class="text-zinc-700 dark:text-zinc-300">Integrate SCR signing into CI/CD</span>
            </li>
            <li class="flex items-center gap-2">
              <input type="checkbox" class="rounded" />
              <span class="text-zinc-700 dark:text-zinc-300">Audit LIDs quarterly for stale entries</span>
            </li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">Appendix B: FAQ</h2>
          <dl class="space-y-3 text-sm">
            <div>
              <dt class="font-semibold text-zinc-800 dark:text-zinc-200 mb-1">Q: Can LIDs be used for non-web UIs?</dt>
              <dd class="text-zinc-700 dark:text-zinc-300">✅ Yes (e.g., <code class="text-xs bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded break-all">lid://mobile.app/ios/settings#notifications</code>)</dd>
            </div>
            <div>
              <dt class="font-semibold text-zinc-800 dark:text-zinc-200 mb-1">Q: How to handle microfrontends?</dt>
              <dd class="text-zinc-700 dark:text-zinc-300">Use subdomains or path prefixes: <code class="text-xs bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded break-all">lid://checkout.app.com</code> or <code class="text-xs bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded break-all">lid://app.com/@checkout</code></dd>
            </div>
            <div>
              <dt class="font-semibold text-zinc-800 dark:text-zinc-200 mb-1">Q: What if a selector becomes ambiguous?</dt>
              <dd class="text-zinc-700 dark:text-zinc-300">Reduce confidence scores in SCR bundles (e.g., 0.7 → 0.4)</dd>
            </div>
          </dl>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">Why This Matters</h2>
          <p class="text-sm text-zinc-700 dark:text-zinc-300 mb-3">This BCP turns theoretical specs into actionable wisdom, addressing:</p>
          <ul class="list-disc pl-6 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <li><strong>Team Scalability:</strong> Namespacing prevents conflicts</li>
            <li><strong>Maintainability:</strong> TTLs/revocations avoid bundle rot</li>
            <li><strong>Security:</strong> Attestations and key rotation</li>
          </ul>
        </section>

        <section>
          <h2 class="text-lg font-semibold mb-3">License</h2>
          <p class="text-sm text-zinc-700 dark:text-zinc-300">
            CC BY-SA 4.0<br />
            Must include: "Based on LID-RFC-001"
          </p>
        </section>
      </div>
    `,
  }
};

type Section = {
  id: string; title: string; intro?: string; children?: React.ReactNode;
};

const sections: Section[] = [
  {
    id: "01-intro",
    title: "1. Introduction",
    intro: "Linkism defines a protocol for persistent element identity on the web.",
    children: (
      <div className="space-y-4">
        <p>
          LIDs decouple tests, agents, and RPA from brittle DOM structure via immutable contracts,
          signed bundles, and offline resolution.
        </p>
        <p>
          This document consolidates the core LID URI specification (RFC-001) and deployment best practices (BCP-001) 
          into a unified reference for implementers and adopters.
        </p>
        <p>
          Modern web applications suffer from brittle element selectors that break during UI changes. 
          Linkism solves this by providing a standardized URI scheme for persistent element identification 
          that survives framework migrations, redesigns, and time.
        </p>

        <h3 className="text-lg font-semibold">1.1 Protocol Architecture</h3>
        <div className="p-4 bg-zinc-50 dark:bg-zinc-900/20 border border-zinc-200 dark:border-zinc-800 rounded">
          <div className="text-xs text-zinc-600 dark:textinc-400 mb-3">Protocol Flow</div>
          <div className="font-mono text-xs text-zinc-700 dark:text-zinc-300 space-y-1">
            <div className="flex items-center gap-2">
              <div className="w-20 p-1 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-400 rounded text-center">HTML</div>
              <span>→</span>
              <div className="text-zinc-500">contains</div>
              <span>→</span>
              <code className="bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">lid://app.com/auth#login</code>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-20 p-1 bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400 rounded text-center">SCR Bundle</div>
              <span>→</span>
              <div className="text-zinc-500">maps to</div>
              <span>→</span>
              <code className="bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">button.primary</code>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-20 p-1 bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-400 rounded text-center">Resolver</div>
              <span>→</span>
              <div className="text-zinc-500">returns</div>
              <span>→</span>
              <code className="bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">CSS selector + confidence</code>
            </div>
          </div>
        </div>

        <h3 className="text-lg font-semibold">1.2 Key Benefits</h3>
        <ul className="list-disc pl-6 space-y-1">
          <li><strong>Framework Independence:</strong> LIDs survive React → Vue → Angular migrations</li>
          <li><strong>Design System Resilience:</strong> UI redesigns don't break automation</li>
          <li><strong>Cryptographic Integrity:</strong> Signed bundles prevent selector tampering</li>
          <li><strong>Air-Gapped Resolution:</strong> Works without network dependencies</li>
        </ul>
      </div>
    ),
  },
  {
    id: "02-terminology",
    title: "2. Terminology",
    children: (
      <div className="space-y-3">
        <dl className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
            <dt className="font-mono font-semibold">LID</dt>
            <dd className="md:col-span-3">
              Linkism ID - persistent identifier for UI elements
              <a href="#03-lid-uri" className="ml-2 text-xs text-blue-600 dark:text-blue-400 hover:underline">
                (RFC-001 §3)
              </a>
            </dd>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
            <dt className="font-mono font-semibold">Authority</dt>
            <dd className="md:col-span-3">Domain name responsible for LID registration</dd>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
            <dt className="font-mono font-semibold">Path</dt>
            <dd className="md:col-span-3">Hierarchical context for element grouping</dd>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
            <dt className="font-mono font-semibold">Fragment</dt>
            <dd className="md:col-span-3">Specific element identifier</dd>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
            <dt className="font-mono font-semibold">SCR</dt>
            <dd className="md:col-span-3">
              Selector Contract Registry
              <a href="#04-scr" className="ml-2 text-xs text-blue-600 dark:text-blue-400 hover:underline">
                (RFC-002 §4)
              </a>
            </dd>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
            <dt className="font-mono font-semibold">Resolver</dt>
            <dd className="md:col-span-3">
              System translating LID to current selector
              <a href="#05-resolution" className="ml-2 text-xs text-blue-600 dark:text-blue-400 hover:underline">
                (RFC-003 §5)
              </a>
            </dd>
          </div>
        </dl>
      </div>
    ),
  },
  {
    id: "03-lid-uri",
    title: "3. LID URI Specification (RFC-001)",
    intro: "Persistent addressing scheme for UI elements using standardized URI syntax.",
    children: (
      <div className="space-y-4">
        <p>
          The LID URI scheme provides immutable addresses for UI elements that survive 
          framework changes, redesigns, and time. Each LID consists of three components: 
          authority (domain), path (context), and fragment (element identifier).
        </p>
        
        <h3 className="text-lg font-semibold">Core Syntax</h3>
        <pre className="p-3 bg-zinc-100 dark:bg-zinc-900 border rounded text-sm font-mono">
{`lid://authority/path#fragment
lid://app.com/checkout#submit-button
lid://docs.site.com/api/v2#search-input`}
        </pre>
        
        <h3 className="text-lg font-semibold">Key Properties</h3>
        <ul className="list-disc pl-6 space-y-1">
          <li><strong>Immutable:</strong> Authority, path, and fragment never change once registered</li>
          <li><strong>Hierarchical:</strong> Path provides contextual grouping</li>
          <li><strong>Verifiable:</strong> Optional cryptographic attestations for content integrity</li>
          <li><strong>Framework-agnostic:</strong> Works across React, Vue, Angular, etc.</li>
        </ul>
        
        <div className="p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded">
          <p className="text-sm text-blue-700 dark:text-blue-300">
            <strong>💡 Implementation Note:</strong> LIDs decouple test automation and 
            UI tooling from brittle CSS selectors that break during redesigns.
          </p>
        </div>
      </div>
    ),
  },
  {
    id: "04-scr",
    title: "4. SCR Bundle Format (RFC-002)",
    intro: "Cryptographic container for element contracts enabling air-gapped resolution.",
    children: (
      <div className="space-y-4">
        <p>
          Selector Contract Registry (SCR) bundles are signed JSON documents that map 
          LIDs to current CSS selectors. They enable offline resolution and provide 
          cryptographic guarantees about element contracts.
        </p>
        
        <h3 className="text-lg font-semibold">Bundle Contents</h3>
        <ul className="list-disc pl-6 space-y-1">
          <li><strong>Contracts:</strong> LID → selector mappings with confidence scores</li>
          <li><strong>Manifest:</strong> Bundle metadata, TTL, and scope information</li>
          <li><strong>Signatures:</strong> Cryptographic verification chain</li>
          <li><strong>Revocations:</strong> Retired LIDs with optional successors</li>
        </ul>
        
        <h3 className="text-lg font-semibold">Example Contract</h3>
        <pre className="p-3 bg-zinc-100 dark:bg-zinc-900 border rounded text-sm font-mono">
{`{
  "lid": "lid://app.com/auth#login",
  "selector": "form#login > button.primary",
  "confidence": 0.95,
  "attestation": "sha256:abc123..."
}`}
        </pre>
        
        <div className="p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded">
          <p className="text-sm text-green-700 dark:text-green-300">
            <strong>🔒 Security:</strong> All bundles must be cryptographically signed 
            and verified before use in production environments.
          </p>
        </div>
      </div>
    ),
  },
  {
    id: "05-resolution",
    title: "5. Resolution Protocol (RFC-003)",
    intro: "Standard interface for translating LIDs to current selectors via HTTP API.",
    children: (
      <div className="space-y-4">
        <p>
          The Resolution Protocol defines how applications translate LIDs into current 
          CSS selectors using SCR bundles. It supports both networked and air-gapped 
          (offline) resolution workflows.
        </p>
        
        <h3 className="text-lg font-semibold">Resolution Flow</h3>
        <div className="p-3 bg-zinc-50 dark:bg-zinc-900/20 border rounded text-sm">
          <div className="font-mono text-xs space-y-1">
            <div>1. Parse LID URI → Extract authority, path, fragment</div>
            <div>2. Load SCR Bundle → Verify signature and TTL</div>
            <div>3. Lookup Contract → Find matching LID entry</div>
            <div>4. Return Result → Selector + confidence + metadata</div>
          </div>
        </div>
        
        <h3 className="text-lg font-semibold">API Endpoint</h3>
        <pre className="p-3 bg-zinc-100 dark:bg-zinc-900 border rounded text-sm font-mono">
{`POST /v1/resolve-many
{
  "lids": ["lid://app.com/auth#login"],
  "bundle_fingerprint": "sha256:..."
}`}
        </pre>
        
        <div className="p-4 bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded">
          <p className="text-sm text-purple-700 dark:text-purple-300">
            <strong>⚡ Performance:</strong> Resolvers can cache successful resolutions 
            based on TTL values to minimize redundant lookups.
          </p>
        </div>
      </div>
    ),
  },
  {
    id: "06-bcp",
    title: "6. Best Current Practice (BCP-LID-001)",
    intro: "Deployment guidelines and operational recommendations for production LID usage.",
    children: (
      <div className="space-y-4">
        <div className="mb-6 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-xs px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-400 rounded-full">
              BCP-LID-001
            </span>
            <span className="text-sm font-semibold text-blue-800 dark:text-blue-400">
              Deployment Guidelines
            </span>
          </div>
          <p className="text-sm text-blue-700 dark:text-blue-300">
            This section contains Best Current Practice recommendations from BCP-LID-001, 
            available as a separate document for implementers and operations teams.
          </p>
        </div>

        <h3 className="text-lg font-semibold">6.1 LID Naming Conventions</h3>
        <ul className="list-disc pl-6 space-y-1">
          <li><strong>Authority Selection:</strong> Use domains you control; prefer subdomains for teams</li>
          <li><strong>Path Design:</strong> Mirror URL structure, use @ for namespaces</li>
          <li><strong>Fragment Semantics:</strong> Be concise and specific, avoid PII</li>
        </ul>

        <h3 className="text-lg font-semibold">6.2 SCR Bundle Hygiene</h3>
        <ul className="list-disc pl-6 space-y-1">
          <li><strong>Segmentation:</strong> Single bundle for small apps, split for large</li>
          <li><strong>TTL Policies:</strong> Design systems (365 days), checkout flows (90 days), A/B tests (30 days)</li>
          <li><strong>Revocation:</strong> Retire before removal, declare successors</li>
        </ul>

        <h3 className="text-lg font-semibold">6.3 Security & Privacy</h3>
        <ul className="list-disc pl-6 space-y-1">
          <li><strong>Attestation:</strong> Hash critical elements</li>
          <li><strong>Key Rotation:</strong> Annual, publish revoked keys</li>
          <li><strong>PII Mitigation:</strong> Replace PII with hashes</li>
        </ul>

        <h3 className="text-lg font-semibold">6.4 Debugging & Operations</h3>
        <ul className="list-disc pl-6 space-y-1">
          <li><strong>Forensics:</strong> Use <code className="text-xs bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded">linkism audit</code> to trace history</li>
          <li><strong>Triaging:</strong> Check confidence, attestation, TTL</li>
          <li><strong>Monitoring:</strong> Quarterly audits and automated linting</li>
        </ul>

        <h3 className="text-lg font-semibold">6.5 Examples</h3>
        <div className="space-y-3">
          <div>
            <div className="text-sm font-semibold text-green-700 dark:text-green-400 mb-1">✓ Good:</div>
            <code className="text-xs font-mono bg-green-50 dark:bg-green-900/20 px-2 py-1 rounded">lid://shop.com/checkout#apply-promo</code>
          </div>
          <div>
            <div className="text-sm font-semibold text-red-700 dark:text-red-400 mb-1">✗ Avoid:</div>
            <code className="text-xs font-mono bg-red-50 dark:bg-red-900/20 px-2 py-1 rounded">lid://temp.com/modal#close</code>
          </div>
        </div>
      </div>
    ),
  },
  {
    id: "07-implementation",
    title: "7. Reference Implementation",
    intro: "Minimal Rust implementation demonstrating core protocol compliance.",
    children: (
      <div className="space-y-4">
        <p>
          A complete reference implementation in Rust that demonstrates LID parsing, 
          SCR bundle verification, and resolution. Designed for readability and 
          specification compliance rather than production optimization.
        </p>
        
        <h3 className="text-lg font-semibold">Key Features</h3>
        <ul className="list-disc pl-6 space-y-1">
          <li><strong>Zero Dependencies:</strong> Pure functions with no external requirements</li>
          <li><strong>WASM Compatible:</strong> Runs in browsers, servers, and embedded systems</li>
          <li><strong>Crypto-First:</strong> Built-in signature verification and attestation</li>
          <li><strong>Test Coverage:</strong> Comprehensive test suite for all edge cases</li>
        </ul>
        
        <h3 className="text-lg font-semibold">Quick Start</h3>
        <pre className="p-3 bg-zinc-100 dark:bg-zinc-900 border rounded text-sm font-mono">
{`// Parse and resolve a LID
let lid = Lid::parse("lid://app.com/auth#login")?;
let result = bundle.resolve(&lid)?;
println!("Selector: {}", result.selector);`}
        </pre>
        
        <div className="p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded">
          <p className="text-sm text-amber-700 dark:text-amber-300">
            <strong>⚠️ Note:</strong> This is a reference implementation. Production systems 
            should use established cryptographic libraries for signature verification.
          </p>
        </div>
      </div>
    ),
  },
  {
    id: "08-quickstart",
    title: "8. Quickstart Guide",
    intro: "Command-line examples for immediate protocol adoption.",
    children: (
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">8.1 Bundle Generation</h3>
        <pre className="p-4 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded text-sm overflow-x-auto font-mono">
{`# Generate bundle from existing selectors (migration mode)
linkism bundle \\
  --lid lid://app.com/auth#login \\
  --selector 'form#login > button.primary' \\
  --key ./team-key.pem \\
  --output auth.scr

# Batch generation from URL crawl
linkism bundle --url https://app.com --out app.scr`}
        </pre>

        <h3 className="text-lg font-semibold">8.2 Resolution</h3>
        <pre className="p-4 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded text-sm overflow-x-auto font-mono">
{`# Resolve offline
linkism resolve \\
  --lid lid://app.com/checkout#submit \\
  --scr ./app.scr

# Validate bundle integrity
linkism verify-scr app.scr --trust-ring ./keys.pub`}
        </pre>
      </div>
    ),
  },
  {
    id: "09-references",
    title: "9. References",
    children: (
      <div className="space-y-3">
        <h3 className="text-lg font-semibold">9.1 Normative References</h3>
        <dl className="space-y-2 text-sm">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-2">
            <dt className="md:col-span-2 font-mono text-gray-600">[RFC3986]</dt>
            <dd className="md:col-span-10">
              Berners-Lee, T., "Uniform Resource Identifier (URI): Generic Syntax", STD 66, RFC 3986, January 2005.
            </dd>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-12 gap-2">
            <dt className="md:col-span-2 font-mono text-gray-600">[RFC7519]</dt>
            <dd className="md:col-span-10">
              Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)", RFC 7519, May 2015.
            </dd>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-12 gap-2">
            <dt className="md:col-span-2 font-mono text-gray-600">[RFC5280]</dt>
            <dd className="md:col-span-10">
              Cooper, D., Santesson, S., Farrell, S., Boeyen, S., Housley, R., and W. Polk, "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile", RFC 5280, May 2008.
            </dd>
          </div>
        </dl>
      </div>
    ),
  },
];

function LidChevron({open}:{open:boolean}) {
  return (
    <svg aria-hidden viewBox="0 0 20 20" className={`w-3 h-3 mr-2 transition-transform ${open ? "rotate-90" : ""}`}>
      <path fill="currentColor" d="M7 5l6 5-6 5V5z" />
    </svg>
  );
}

function SpecDrawer({ open, onClose, rfc }: { open: boolean; onClose: () => void; rfc: string }) {
  const content = rfcContent[rfc];
  if (!content) return null;

  return (
    <div className={`fixed inset-0 z-50 ${open ? 'block' : 'hidden'}`}>
      <div className="fixed inset-0 bg-black/40 backdrop-blur-sm" onClick={onClose} />
      <div className="fixed inset-0 overflow-y-auto">
        <div className="flex min-h-full items-start justify-end p-4 md:p-8">
          <div className="w-full max-w-3xl transform overflow-hidden rounded-lg bg-white dark:bg-zinc-950 shadow-xl border border-zinc-200 dark:border-zinc-800">
            <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800 px-6 py-4">
              <div className="flex items-center gap-3">
                <h2 className="text-base font-medium text-zinc-900 dark:text-zinc-100">
                  {content.title}
                </h2>
                <span className={`text-xs px-2 py-1 rounded-full ${
                  content.status === 'stable' 
                    ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400' 
                    : 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-400'
                }`}>
                  {content.status.toUpperCase()}
                </span>
              </div>
              <div className="flex items-center gap-4">
                <a
                  href={`${content.pdf}?v=1.0`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-blue-600 dark:text-blue-400 hover:underline decoration-dotted"
                >
                  Download PDF
                </a>
                <button
                  onClick={onClose}
                  className="text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 text-lg"
                  aria-label="Close specification document"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>
            <div className="p-6 max-h-[80vh] overflow-y-auto">
              <div 
                className="prose dark:prose-invert prose-sm max-w-none"
                dangerouslySetInnerHTML={{ __html: content.html }} 
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Accordion({label, children}:{label:string; children:React.ReactNode}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border-b border-zinc-200 dark:border-zinc-800">
      <button
        onClick={() => setOpen(o=>!o)}
        className="w-full flex items-center justify-between py-3 text-left hover:bg-zinc-50 dark:hover:bg-zinc-900/40"
        aria-expanded={open}
      >
        <span className="flex items-center">
          <LidChevron open={open} />
          <span className="underline decoration-dotted text-sm">{label}</span>
        </span>
        <span className="text-xs text-zinc-500">{open ? "close" : "open"}</span>
      </button>
      {open && <div className="pb-4 pl-5 text-sm text-zinc-600 dark:text-zinc-300">{children}</div>}
    </div>
  );
}

export default function LinkismProtocolSpec() {
  const [idx, setIdx] = useState(0);
  const [selectedRFC, setSelectedRFC] = useState<string | null>(null);
  const current = sections[idx];
  const tocRef = useRef<HTMLDivElement>(null);

  // Simplified keyboard navigation (j/k only)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "j") setIdx(i => Math.min(i + 1, sections.length - 1));
      if (e.key === "k") setIdx(i => Math.max(i - 1, 0));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const year = useMemo(() => new Date().getFullYear(), []);

  return (
    <div className="min-h-screen bg-white text-zinc-900 dark:bg-zinc-950 dark:text-zinc-100">
      <header className="border-b border-zinc-200 dark:border-zinc-800 sticky top-0 bg-white/90 dark:bg-zinc-950/90 backdrop-blur">
        <div className="mx-auto max-w-4xl px-6 py-4 flex items-baseline justify-between">
          <div>
            <div className="text-sm tracking-wide font-semibold">Linkism Protocol</div>
            <div className="text-xs text-zinc-500 mt-0.5">Persistent UI Addressing Standard</div>
          </div>
          <div className="flex items-center space-x-4 text-xs text-zinc-500">
            <span className="font-mono text-green-600 dark:text-green-400">RFC Suite v1.0</span>
            <span className="text-zinc-400">Mar 2025</span>
            <a
              href="/linkism-protocol-v1.pdf?v=1.0"
              className="flex items-center space-x-1 text-blue-600 dark:text-blue-400 hover:underline decoration-dotted"
              target="_blank"
              rel="noopener noreferrer"
            >
              <svg className="w-3 h-3" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
              <span>PDF</span>
            </a>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-6 py-10">
        {/* Document metadata */}
        <div className="mb-8 pb-6 border-b border-zinc-200 dark:border-zinc-800 text-xs text-zinc-600 dark:text-zinc-400">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-1">
              <div><span className="font-semibold">Author:</span> Joel David Trout II</div>
              <div><span className="font-semibold">Category:</span> Standards Track</div>
              <div><span className="font-semibold">Status:</span> Draft</div>
            </div>
            <div className="space-y-1">
              <div><span className="font-semibold">Created:</span> January 2025</div>
              <div><span className="font-semibold">License:</span> CC BY-SA 4.0</div>
              <div><span className="font-semibold">Updates:</span> None</div>
            </div>
          </div>
        </div>

        {/* TOC */}
        <aside
          ref={tocRef}
          className="mb-10 p-4 border border-zinc-200 dark:border-zinc-800 rounded bg-zinc-50 dark:bg-zinc-900/20"
        >
          <div className="text-xs uppercase tracking-wide text-zinc-500 mb-3">Table of Contents</div>
          <ol className="space-y-1 text-sm">
            {sections.map((s, i) => {
              const shouldOpenOverlay = s.id === "03-lid-uri" || s.id === "04-scr" || s.id === "05-resolution" || s.id === "06-bcp" || s.id === "07-implementation";
              const rfcMap = {
                "03-lid-uri": "rfc-001",
                "04-scr": "rfc-002", 
                "05-resolution": "rfc-003",
                "06-bcp": "bcp-001",
                "07-implementation": "reference-impl"
              };
              
              return (
                <li key={s.id}>
                  <button
                    onClick={() => setIdx(i)} // Always navigate to section summary
                    className={`w-full text-left px-3 py-1.5 rounded-md transition-all ${
                      i === idx
                        ? "font-semibold bg-zinc-100 dark:bg-zinc-900 border-l-2 border-blue-500 text-zinc-900 dark:text-zinc-100"
                        : "text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-900"
                    }`}
                  >
                    <span className="flex items-center justify-between">
                      <span>{s.title}</span>
                      {shouldOpenOverlay && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation(); // Prevent section navigation
                            setSelectedRFC(rfcMap[s.id as keyof typeof rfcMap]); // Open overlay instead
                          }}
                          className="px-2 py-1 ml-2 text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 rounded transition-colors"
                          aria-label="View detailed specification"
                        >
                          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                          </svg>
                        </button>
                      )}
                    </span>
                  </button>
                </li>
              );
            })}
          </ol>
          <div className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 text-xs text-zinc-500">
            Use <kbd className="px-1 py-0.5 bg-zinc-200 dark:bg-zinc-800 rounded text-xs">j</kbd>/<kbd className="px-1 py-0.5 bg-zinc-200 dark:bg-zinc-800 rounded text-xs">k</kbd> to navigate sections
          </div>
        </aside>

        {/* Current section */}
        <article className="mb-12">
          <section aria-labelledby={`section-${current.id}`}>
            <h1 id={`section-${current.id}`} className="text-2xl md:text-3xl font-serif mb-3 flex items-center">
              {current.title}
              {current.id === "03-lid-uri" && (
                <span className="ml-3 text-xs px-2 py-1 bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400 rounded-full">
                  RFC-001
                </span>
              )}
              {current.id === "06-bcp" && (
                <span className="ml-3 text-xs px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-400 rounded-full">
                  BCP-001
                </span>
              )}
            </h1>
            {current.intro && <p className="text-zinc-600 dark:text-zinc-400 mb-6 text-lg leading-relaxed">{current.intro}</p>}
            <div className="prose prose-zinc dark:prose-invert max-w-none font-serif leading-relaxed">
              {current.children}
            </div>
          </section>
        </article>

        {/* Navigation */}
        <nav className="mt-12 pt-6 border-t border-zinc-200 dark:border-zinc-800 flex items-center justify-between text-sm">
          <button
            onClick={() => setIdx(i => Math.max(i - 1, 0))}
            disabled={idx === 0}
            className="underline decoration-dotted hover:no-underline disabled:opacity-40 disabled:cursor-not-allowed"
          >
            ← Previous
          </button>
          <div className="text-xs text-zinc-500">Section {idx + 1} of {sections.length}</div>
          <button
            onClick={() => setIdx(i => Math.min(i + 1, sections.length - 1))}
            disabled={idx === sections.length - 1}
            className="underline decoration-dotted hover:no-underline disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Next →
          </button>
        </nav>
      </main>

      {/* Footer as LID accordions */}
      <footer className="mt-16 border-t border-zinc-200 dark:border-zinc-800">
        <div className="mx-auto max-w-4xl px-6 py-8">
          <Accordion label="lid://protocol/specs">
            <ul className="space-y-2">
              <li>
                <button 
                  onClick={() => setSelectedRFC('rfc-001')}
                  className="underline decoration-dotted hover:no-underline text-left flex items-center gap-2"
                >
                  RFC-001 · LID URI Specification
                  <span className="text-xs px-1.5 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400 rounded-sm">
                    STABLE
                  </span>
                </button>
              </li>
              <li>
                <button 
                  onClick={() => setSelectedRFC('rfc-002')}
                  className="underline decoration-dotted hover:no-underline text-left flex items-center gap-2"
                >
                  RFC-002 · SCR Bundle Format
                  <span className="text-xs px-1.5 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400 rounded-sm">
                    STABLE
                  </span>
                </button>
              </li>
              <li>
                <button 
                  onClick={() => setSelectedRFC('rfc-003')}
                  className="underline decoration-dotted hover:no-underline text-left flex items-center gap-2"
                >
                  RFC-003 · Resolution Protocol
                  <span className="text-xs px-1.5 py-0.5 bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-400 rounded-sm">
                    DRAFT
                  </span>
                </button>
              </li>
              <li>
                <button 
                  onClick={() => setSelectedRFC('bcp-001')}
                  className="underline decoration-dotted hover:no-underline text-left flex items-center gap-2"
                >
                  BCP-001 · Deployment Guidelines
                  <span className="text-xs px-1.5 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400 rounded-sm">
                    STABLE
                  </span>
                </button>
              </li>
            </ul>
          </Accordion>
          <Accordion label="lid://protocol/implementation">
            <ul className="space-y-2">
              <li>
                <button 
                  onClick={() => setSelectedRFC('reference-impl')}
                  className="underline decoration-dotted hover:no-underline text-left flex items-center gap-2"
                >
                  Reference Implementation (Rust)
                  <span className="text-xs px-1.5 py-0.5 bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-400 rounded-sm">
                    COMPLETE
                  </span>
                </button>
              </li>
              <li><a className="underline decoration-dotted hover:no-underline" href="/conformance">Conformance Test Suite</a></li>
              <li><a className="underline decoration-dotted hover:no-underline" href="/examples">Integration Examples</a></li>
            </ul>
          </Accordion>
          <Accordion label="lid://protocol/community">
            <ul className="space-y-2">
              <li><a className="underline decoration-dotted hover:no-underline" href="https://github.com/linkism-rfcs" target="_blank" rel="noopener noreferrer">RFCs on GitHub</a></li>
              <li><a className="underline decoration-dotted hover:no-underline" href="/discuss">Protocol Discussions</a></li>
              <li><a className="underline decoration-dotted hover:no-underline" href="/contributing">Contributing Guidelines</a></li>
            </ul>
          </Accordion>
          
          <div className="mt-6 pt-4 border-t border-zinc-200 dark:border-zinc-800 text-xs text-zinc-500">
            © {year} Linkism Protocol — Open specification, royalty-free implementation
          </div>
        </div>
      </footer>

      {/* RFC Drawer */}
      {selectedRFC && (
        <SpecDrawer
          open={!!selectedRFC}
          onClose={() => setSelectedRFC(null)}
          rfc={selectedRFC}
        />
      )}

      {/* Print styles */}
      <style jsx global>{`
        @media print {
          header, nav, footer { display: none !important; }
          main { max-width: 100% !important; padding: 0 !important; }
          article { page-break-after: always; }
          a[href]:after { content: " (" attr(href) ")"; font-size: 0.8em; color: #666; }
          pre { white-space: pre-wrap; word-wrap: break-word; page-break-inside: avoid; }
          .prose { font-size: 12pt; line-height: 1.4; }
        }
        
        @media (prefers-reduced-motion: reduce) {
          * { transition: none !important; animation: none !important; }
        }
      `}</style>
    </div>
  );
}
