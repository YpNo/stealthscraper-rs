//! Geo/locale consistency: country codes, a curated country -> locale table, and
//! a resolver port for discovering a proxy's exit country.
//!
//! Modern anti-bot systems cross-check the egress IP's geolocation against the
//! browser's declared locale (Accept-Language, `navigator.languages`, timezone).
//! A mismatch — e.g. a German IP with a US English, `America/New_York` browser —
//! is a strong bot signal. This module supplies the building blocks the scraper
//! uses to keep those layers coherent, **proxy-led**: the egress proxy's country
//! is the source of truth and the browser locale is derived to match.

/// An ISO 3166-1 alpha-2 country code (stored uppercase, e.g. `DE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    /// Parse a two-letter country code, normalising to uppercase.
    ///
    /// Returns `None` unless the input is exactly two ASCII letters.
    pub fn new(code: &str) -> Option<Self> {
        let bytes = code.as_bytes();
        if bytes.len() == 2 && bytes.iter().all(u8::is_ascii_alphabetic) {
            Some(Self([
                bytes[0].to_ascii_uppercase(),
                bytes[1].to_ascii_uppercase(),
            ]))
        } else {
            None
        }
    }

    /// The uppercase two-letter code as a string slice.
    pub fn as_str(&self) -> &str {
        // SAFETY-equivalent: bytes are ASCII letters by construction in `new`.
        std::str::from_utf8(&self.0).expect("country code is valid ASCII by construction")
    }
}

impl std::fmt::Display for CountryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A coherent locale bundle for a country: the values that must agree with the
/// egress IP across the HTTP, JS, and timezone layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locale {
    /// The country this locale represents.
    pub country: CountryCode,
    /// `Accept-Language` header value (e.g. `de-DE,de;q=0.9,en;q=0.8`).
    pub accept_language: String,
    /// `navigator.languages` list (e.g. `["de-DE", "de", "en"]`).
    pub languages: Vec<String>,
    /// IANA timezone id (e.g. `Europe/Berlin`).
    pub timezone: String,
}

impl Locale {
    /// The curated locale for a country, or `None` if we have no data for it.
    ///
    /// The table is intentionally a representative subset; unknown countries
    /// return `None` so the caller can fall back rather than apply a wrong locale.
    pub fn for_country(country: CountryCode) -> Option<Self> {
        let (accept_language, languages, timezone): (&str, &[&str], &str) = match country.as_str() {
            "US" => ("en-US,en;q=0.9", &["en-US", "en"], "America/New_York"),
            "GB" => ("en-GB,en;q=0.9", &["en-GB", "en"], "Europe/London"),
            "CA" => (
                "en-CA,en;q=0.9,fr-CA;q=0.8",
                &["en-CA", "en", "fr-CA"],
                "America/Toronto",
            ),
            "AU" => ("en-AU,en;q=0.9", &["en-AU", "en"], "Australia/Sydney"),
            "DE" => (
                "de-DE,de;q=0.9,en;q=0.8",
                &["de-DE", "de", "en"],
                "Europe/Berlin",
            ),
            "FR" => (
                "fr-FR,fr;q=0.9,en;q=0.8",
                &["fr-FR", "fr", "en"],
                "Europe/Paris",
            ),
            "ES" => (
                "es-ES,es;q=0.9,en;q=0.8",
                &["es-ES", "es", "en"],
                "Europe/Madrid",
            ),
            "IT" => (
                "it-IT,it;q=0.9,en;q=0.8",
                &["it-IT", "it", "en"],
                "Europe/Rome",
            ),
            "NL" => (
                "nl-NL,nl;q=0.9,en;q=0.8",
                &["nl-NL", "nl", "en"],
                "Europe/Amsterdam",
            ),
            "PL" => (
                "pl-PL,pl;q=0.9,en;q=0.8",
                &["pl-PL", "pl", "en"],
                "Europe/Warsaw",
            ),
            "SE" => (
                "sv-SE,sv;q=0.9,en;q=0.8",
                &["sv-SE", "sv", "en"],
                "Europe/Stockholm",
            ),
            "BR" => (
                "pt-BR,pt;q=0.9,en;q=0.8",
                &["pt-BR", "pt", "en"],
                "America/Sao_Paulo",
            ),
            "MX" => (
                "es-MX,es;q=0.9,en;q=0.8",
                &["es-MX", "es", "en"],
                "America/Mexico_City",
            ),
            "JP" => (
                "ja-JP,ja;q=0.9,en;q=0.8",
                &["ja-JP", "ja", "en"],
                "Asia/Tokyo",
            ),
            "IN" => (
                "en-IN,en;q=0.9,hi;q=0.8",
                &["en-IN", "en", "hi"],
                "Asia/Kolkata",
            ),
            _ => return None,
        };
        Some(Self {
            country,
            accept_language: accept_language.to_string(),
            languages: languages.iter().map(|s| (*s).to_string()).collect(),
            timezone: timezone.to_string(),
        })
    }

    /// The primary BCP-47 language tag (first in [`Self::languages`]), used for
    /// CDP `Emulation.setLocaleOverride`.
    pub fn primary_language(&self) -> &str {
        self.languages.first().map_or("en-US", String::as_str)
    }
}

/// Output port for discovering the exit country of a proxy URL.
///
/// Implementations may consult a local GeoIP database or a remote API. None ship
/// by default (to avoid bundling data files or making network calls); explicit
/// per-proxy country tags are the dependency-free path, with this port as the
/// pluggable fallback for dynamic resolution.
pub trait GeoResolver: Send + Sync {
    /// Best-effort country for the given proxy URL, or `None` if unknown.
    fn country_of(&self, proxy_url: &str) -> Option<CountryCode>;
}

/// Parse an `Accept-Language` header into an ordered `navigator.languages` list,
/// dropping the `;q=` quality weights (e.g. `de-DE,de;q=0.9` -> `["de-DE","de"]`).
pub fn languages_from_accept_language(accept_language: &str) -> Vec<String> {
    accept_language
        .split(',')
        .filter_map(|part| {
            let tag = part.split(';').next()?.trim();
            (!tag.is_empty()).then(|| tag.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_code_parses_and_normalises() {
        assert_eq!(CountryCode::new("de").unwrap().as_str(), "DE");
        assert_eq!(CountryCode::new("US").unwrap().to_string(), "US");
        assert!(CountryCode::new("USA").is_none());
        assert!(CountryCode::new("1").is_none());
        assert!(CountryCode::new("u1").is_none());
    }

    #[test]
    fn locale_for_known_country_is_coherent() {
        let de = Locale::for_country(CountryCode::new("DE").unwrap()).unwrap();
        assert_eq!(de.timezone, "Europe/Berlin");
        assert_eq!(de.languages, vec!["de-DE", "de", "en"]);
        assert!(de.accept_language.starts_with("de-DE"));
        assert_eq!(de.primary_language(), "de-DE");
    }

    #[test]
    fn locale_for_unknown_country_is_none() {
        assert!(Locale::for_country(CountryCode::new("ZZ").unwrap()).is_none());
    }

    #[test]
    fn languages_from_accept_language_strips_quality() {
        assert_eq!(
            languages_from_accept_language("de-DE,de;q=0.9,en;q=0.8"),
            vec!["de-DE", "de", "en"]
        );
        assert_eq!(
            languages_from_accept_language("en-US,en;q=0.9"),
            vec!["en-US", "en"]
        );
        assert!(languages_from_accept_language("").is_empty());
    }
}
