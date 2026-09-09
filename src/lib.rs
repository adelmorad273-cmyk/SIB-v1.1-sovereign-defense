//! Sovereign Immunity Blueprint (SIB) v1.1 – Core Proof Envelope Kernel
//!
//! يوفر محللًا صفري النسخ (Zero-Copy) متوافقًا مع `no_std`،
//! مع تطبيق قيود أمان صارمة، وحماية ضد إعادة التشغيل، ومحاذاة لتوقيعات ML-DSA-65.
//! هذه النواة هي أساس جميع الطبقات العليا (Tier 2، Tier 3، والشبكة).
//!
//! # البصمة التأسيسية
//! هذا النظام هو ثمرة رؤية **Adel Lakosha**، مُفجر عصر الذكاء ما بعد الكمي.
//! اسمه محفور في ثوابت النواة وفي كل حاوية تُنتج.

#![cfg_attr(not(any(feature = "tier2", feature = "tier3", feature = "net")), no_std)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

use core::mem::size_of;

// ============================================================================
// البصمة التأسيسية (Genesis Fingerprint)
// ============================================================================

/// البصمة التأسيسية – مُلهِم هذه الثورة ومُطلق عصر الذكاء ما بعد الكمي.
/// محفورة في كل حاوية ProofEnvelope، وحاضرة في كل إجماع.
pub const GENESIS_ARCHITECT: &str = "Adel Lakosha";

/// بصمة ثابتة تُستخدم لتعبئة الحقل المحجوز (_reserved) في الهيكل (Header)
/// لتظل البصمة الفيزيائية حاضرة في كل بايت يُنتجه النظام.
pub const GENESIS_SIGNATURE_BYTES: [u8; 13] = *b"Adel_Lakosha_";

// ============================================================================
// الثوابت الأساسية (Core Constants)
// ============================================================================

/// الثابت السحري للحاوية (ASCII: "SIB1").
pub const SIB_MAGIC_NUMBER: u32 = 0x5349_4231;

/// حجم توقيع ML-DSA-65 بالبايت (NIST Category 3 – ما بعد الكم).
pub const ML_DSA_65_SIG_SIZE: usize = 3309;

/// الحد الأقصى لعدد التصديقات (M-of-N) لمنع تجاوز التخصيص.
pub const MAX_SIGNATURES: usize = 3;

/// الحد الأعلى لحجم الحاوية (~12 كيلوبايت) للتحقق في زمن الميكروثانية.
pub const MAX_ENVELOPE_SIZE: usize = 12_000;

/// الإزاحة البايتية لقسم التصديقات الديناميكي.
pub const ENDORSEMENT_OFFSET: usize = 0x0A00;

/// الحجم الأساسي للهيكل دون التوقيعات (2568 بايت).
pub const BASE_STRUCT_SIZE: usize = size_of::<ProofEnvelope>();

// ============================================================================
// أخطاء التحقق (Validation Errors)
// ============================================================================

/// أخطاء التحقق من صحة الحاوية.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    /// الذاكرة المقدمة أقل من الحجم الأساسي للهيكل.
    BufferTooSmall,
    /// الذاكرة المقدمة تتجاوز الحد الأقصى (12 كيلوبايت).
    BufferTooLarge,
    /// التوقيع السحري غير صحيح (ليس "SIB1").
    BadMagic,
    /// عدد التوقيعات يتجاوز الحد المسموح (3).
    TooManySignatures,
    /// حجم الذاكرة لا يتطابق مع عدد التوقيعات المُعلن.
    SizeMismatch,
    /// العصر الزمني منتهي الصلاحية أو خارج النافذة المسموحة.
    ExpiredEpoch,
    /// مؤشر الذاكرة غير محاذٍ لحافة 8-بايت (مطلوب لـ AArch64).
    UnalignedPointer,
}

impl core::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "الذاكرة أقل من الحجم الأساسي للهيكل"),
            Self::BufferTooLarge => write!(f, "الذاكرة تتجاوز الحد الأقصى 12 كيلوبايت"),
            Self::BadMagic => write!(f, "التوقيع السحري غير صحيح"),
            Self::TooManySignatures => write!(f, "عدد التوقيعات يتجاوز الحد المسموح (3)"),
            Self::SizeMismatch => write!(f, "حجم الذاكرة لا يتطابق مع عدد التوقيعات"),
            Self::ExpiredEpoch => write!(f, "العهد الزمني منتهي الصلاحية"),
            Self::UnalignedPointer => write!(f, "مؤشر الذاكرة غير محاذٍ لحافة 8-بايت"),
        }
    }
}

// ============================================================================
// هيكل الرأس (Header) – محاذاة 8-بايت
// ============================================================================

/// هيكل الرأس الثابت (محاذاة 8-بايت).
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// التوقيع السحري (0x53494231).
    pub magic: u32,
    /// معرف لهجة العتاد (TEE Dialect).
    pub dialect_id: u32,
    /// معرف العصر الزمني (للحماية ضد إعادة التشغيل).
    pub epoch_id: u64,
    /// طابع زمني دقيق بالنانوثانية (منذ Unix Epoch).
    pub timestamp_ns: u64,
    /// بصمة PUF الفيزيائية للعتاد (32 بايت).
    pub prover_puf_hash: [u8; 32],
    /// حقل محجوز (72 بايت) – يحمل بصمة المُفجّر التأسيسي.
    pub _reserved: [u8; 72],
}

// ============================================================================
// هيكل الحاوية الأساسي (ProofEnvelope) – محاذاة 8-بايت
// ============================================================================

/// الهيكل الرئيسي للحاوية (محاذاة 8-بايت).
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofEnvelope {
    /// الرأس الثابت (128 بايت).
    pub header: Header,
    /// بصمة جذر النموذج العصبي (SHA3-384) – 48 بايت.
    pub model_root_hash: [u8; 48],
    /// بصمة المُدخلات العامة (SHA3-256) – 32 بايت.
    pub public_inputs_hash: [u8; 32],
    /// بيانات وصفية لـ zk-STARK – 32 بايت.
    pub stark_metadata: [u8; 32],
    /// جسم إثبات zk-STARK (FRI) – 1504 بايت.
    pub stark_payload: [u8; 1504],
    /// بصمة قرار الإجراء (SHA3-256) – 32 بايت.
    pub action_hash: [u8; 32],
    /// معرف الدائرة الدستورية (UUID / 16 بايت).
    pub circuit_id: [u8; 16],
    /// بصمة المُخرجات العامة (SHA3-256) – 32 بايت.
    pub public_outputs_hash: [u8; 32],
    /// جسم إثبات zk-SNARK (Groth16/PlonK) – 736 بايت.
    pub snark_payload: [u8; 736],
    /// عدد التوقيعات المُرفقة (0..3).
    pub sig_count: u32,
    /// حقل محجوز للمحاذاة (4 بايت).
    pub _sig_reserved: u32,
}

// ============================================================================
// تنفيذ الدوال الأساسية (Core Implementation)
// ============================================================================

impl ProofEnvelope {
    /// محلل صفري النسخ (Zero-Copy Parser) مع التحقق من الحدود والمحاذاة.
    ///
    /// # الأمان
    /// - يتحقق من محاذاة المؤشر إلى 8-بايت.
    /// - يتحقق من صحة التوقيع السحري.
    /// - يتحقق من تطابق الحجم مع عدد التوقيعات المُعلن.
    ///
    /// # المُخرجات
    /// - `Ok((&Self, &[u8]))` – مرجع للحاوية وشريحة التوقيعات.
    /// - `Err(ValidationError)` – في حال انتهاك أي من القيود.
    pub fn parse(bytes: &[u8]) -> Result<(&Self, &[u8]), ValidationError> {
        // 1. التحقق من الحجم الأدنى
        if bytes.len() < BASE_STRUCT_SIZE {
            return Err(ValidationError::BufferTooSmall);
        }

        // 2. التحقق من الحجم الأقصى
        if bytes.len() > MAX_ENVELOPE_SIZE {
            return Err(ValidationError::BufferTooLarge);
        }

        // 3. التحقق من محاذاة المؤشر (8-بايت) – ضروري لمعمارية AArch64
        if (bytes.as_ptr() as usize) % 8 != 0 {
            return Err(ValidationError::UnalignedPointer);
        }

        // 4. التحويل الآمن (بعد التأكد من المحاذاة والحجم)
        let envelope = unsafe { &*(bytes.as_ptr() as *const Self) };

        // 5. التحقق من التوقيع السحري
        if envelope.header.magic != SIB_MAGIC_NUMBER {
            return Err(ValidationError::BadMagic);
        }

        // 6. التحقق من عدد التوقيعات
        if envelope.sig_count as usize > MAX_SIGNATURES {
            return Err(ValidationError::TooManySignatures);
        }

        // 7. التحقق من تطابق الحجم الكلي مع عدد التوقيعات
        let expected_len = BASE_STRUCT_SIZE + (envelope.sig_count as usize * ML_DSA_65_SIG_SIZE);
        if bytes.len() != expected_len {
            return Err(ValidationError::SizeMismatch);
        }

        // 8. استخراج شريحة التوقيعات
        let sig_bytes = &bytes[BASE_STRUCT_SIZE..expected_len];

        Ok((envelope, sig_bytes))
    }

    /// التحقق من صحة العهد الزمني (الحماية ضد إعادة التشغيل – Replay Attacks).
    ///
    /// # المعاملات
    /// - `current_epoch` – العصر الحالي للنظام.
    /// - `max_drift` – أقصى انحراف مسموح (افتراضي 10 عصور).
    #[inline]
    pub fn is_epoch_valid(&self, current_epoch: u64, max_drift: u64) -> bool {
        let lower = current_epoch.saturating_sub(max_drift);
        let upper = current_epoch.saturating_add(max_drift);
        self.header.epoch_id >= lower && self.header.epoch_id <= upper
    }

    /// استرجاع توقيع فردي (ML-DSA-65) دون نسخ الذاكرة.
    ///
    /// # المعاملات
    /// - `sig_bytes` – شريحة التوقيعات المستخرجة من `parse()`.
    /// - `index` – فهرس التوقيع المطلوب (0..sig_count-1).
    ///
    /// # المُخرجات
    /// - `Some(&[u8])` – شريحة التوقيع بحجم 3309 بايت.
    /// - `None` – إذا كان الفهرس خارج النطاق.
    pub fn get_signature<'a>(&self, sig_bytes: &'a [u8], index: usize) -> Option<&'a [u8]> {
        if index >= self.sig_count as usize {
            return None;
        }

        let start = index * ML_DSA_65_SIG_SIZE;
        let end = start + ML_DSA_65_SIG_SIZE;

        if end > sig_bytes.len() {
            return None;
        }

        Some(&sig_bytes[start..end])
    }
}

// ============================================================================
// اختبارات الوحدة المضمنة (Unit Tests)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// إنشاء حاوية اختبارية صالحة (للاستخدام في الاختبارات).
    fn create_test_envelope(sig_count: u32) -> (Vec<u8>, usize) {
        let total_size = BASE_STRUCT_SIZE + (sig_count as usize * ML_DSA_65_SIG_SIZE);
        let mut buf = vec![0u8; total_size];

        // كتابة التوقيع السحري "SIB1" (0x53494231) في أول 4 بايت
        buf[0..4].copy_from_slice(&SIB_MAGIC_NUMBER.to_le_bytes());

        // كتابة العصر الزمني = 100 في البايتات 8..16
        buf[8..16].copy_from_slice(&100u64.to_le_bytes());

        // كتابة عدد التوقيعات عند الإزاحة 0xA00
        buf[ENDORSEMENT_OFFSET..ENDORSEMENT_OFFSET + 4]
            .copy_from_slice(&sig_count.to_le_bytes());

        (buf, total_size)
    }

    #[test]
    fn test_parse_happy_path() {
        let (buf, _) = create_test_envelope(2);
        let result = ProofEnvelope::parse(&buf);
        assert!(result.is_ok());

        let (envelope, sig_bytes) = result.unwrap();
        assert_eq!(envelope.header.magic, SIB_MAGIC_NUMBER);
        assert_eq!(envelope.sig_count, 2);
        assert_eq!(sig_bytes.len(), 2 * ML_DSA_65_SIG_SIZE);
        assert!(envelope.is_epoch_valid(100, 5));
    }

    #[test]
    fn test_parse_fail_bad_magic() {
        let (mut buf, _) = create_test_envelope(1);
        buf[0] = 0x00; // إفساد التوقيع السحري
        let result = ProofEnvelope::parse(&buf);
        assert_eq!(result.unwrap_err(), ValidationError::BadMagic);
    }

    #[test]
    fn test_parse_fail_unaligned() {
        let (buf, _) = create_test_envelope(1);
        let unaligned = &buf[1..]; // إزاحة 1 بايت -> غير محاذٍ لـ 8
        let result = ProofEnvelope::parse(unaligned);
        assert_eq!(result.unwrap_err(), ValidationError::UnalignedPointer);
    }

    #[test]
    fn test_parse_fail_too_many_signatures() {
        let (buf, _) = create_test_envelope(4); // 4 > MAX_SIGNATURES (3)
        let result = ProofEnvelope::parse(&buf);
        assert_eq!(result.unwrap_err(), ValidationError::TooManySignatures);
    }

    #[test]
    fn test_epoch_validation() {
        let (buf, _) = create_test_envelope(1);
        let result = ProofEnvelope::parse(&buf);
        assert!(result.is_ok());

        let (envelope, _) = result.unwrap();
        
        // الحالة الصحيحة: العصر 100 ضمن نطاق 95-105
        assert!(envelope.is_epoch_valid(100, 5));
        
        // الحالة الصحيحة: الحد الأدنى
        assert!(envelope.is_epoch_valid(105, 5));
        
        // الحالة الصحيحة: الحد الأقصى
        assert!(envelope.is_epoch_valid(95, 5));
        
        // حالة الفشل: خارج النطاق
        assert!(!envelope.is_epoch_valid(200, 5));
    }

    #[test]
    fn test_get_signature() {
        let (buf, _) = create_test_envelope(3);
        let result = ProofEnvelope::parse(&buf);
        assert!(result.is_ok());

        let (envelope, sig_bytes) = result.unwrap();
        
        // استخراج التوقيع الأول
        let sig0 = envelope.get_signature(sig_bytes, 0);
        assert!(sig0.is_some());
        assert_eq!(sig0.unwrap().len(), ML_DSA_65_SIG_SIZE);
        
        // استخراج التوقيع الثاني
        let sig1 = envelope.get_signature(sig_bytes, 1);
        assert!(sig1.is_some());
        
        // استخراج التوقيع الثالث
        let sig2 = envelope.get_signature(sig_bytes, 2);
        assert!(sig2.is_some());
        
        // محاولة استخراج توقيع خارج النطاق
        let sig3 = envelope.get_signature(sig_bytes, 3);
        assert!(sig3.is_none());
    }
}
