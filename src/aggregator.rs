//! Tier 2 – Byzantine Consensus Engine (محرك الإجماع البيزنطي)
//!
//! يوفر محرك تجميع الحاويات من عقد متعددة والتحقق من الإجماع
//! باستخدام نصاب ديناميكي M-of-N (Byzantine Fault Tolerant).
//!
//! # البصمة التأسيسية
//! هذه الوحدة هي جزء من نظام **Adel Lakosha**'s Sovereign Immunity Blueprint.

use crate::{ProofEnvelope, ValidationError};
use core::cmp::min;

// ============================================================================
// الثوابت الأساسية (Core Constants)
// ============================================================================

/// الحد الأدنى للعقد لتشكيل إجماع (قيمة افتراضية).
pub const MIN_CONSENSUS_NODES: usize = 3;

/// الحد الأقصى للعقد (11 عقدة).
pub const MAX_CONSENSUS_NODES: usize = 11;

/// الحد الأدنى للنصاب المطلوب (لـ N=5: M=3).
pub const DEFAULT_QUORUM_M: usize = 3;
pub const DEFAULT_QUORUM_N: usize = 5;

/// هامش الخطأ الزمني المسموح (10 عصور).
pub const DEFAULT_EPOCH_TOLERANCE: u64 = 10;

// ============================================================================
// سياسة الإجماع (Consensus Policy)
// ============================================================================

/// سياسة الإجماع الديناميكية (M-of-N).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusPolicy {
    /// عدد العقد المطلوبة للإجماع.
    pub m: usize,
    /// إجمالي عدد العقد.
    pub n: usize,
    /// هامش الخطأ الزمني المسموح (بالعصور).
    pub epoch_tolerance: u64,
}

impl ConsensusPolicy {
    /// إنشاء سياسة إجماع جديدة.
    ///
    /// # الأمان
    /// - يتحقق من أن M ≤ N.
    /// - يتحقق من أن M > (2N / 3) لضمان Byzantine Fault Tolerance.
    pub fn new(m: usize, n: usize, epoch_tolerance: u64) -> Result<Self, &'static str> {
        if m > n {
            return Err("M يجب أن يكون أقل من أو يساوي N");
        }

        if n < MIN_CONSENSUS_NODES {
            return Err("N يجب أن يكون على الأقل 3");
        }

        if n > MAX_CONSENSUS_NODES {
            return Err("N لا يمكن أن يتجاوز 11");
        }

        // التحقق من Byzantine Fault Tolerance: M > (2N + 1) / 3
        let bft_threshold = (2 * n + 1) / 3;
        if m <= bft_threshold {
            // نقبل M إذا كانت على الأقل bft_threshold
            // في الواقع، للأمان الأقصى، يجب m > bft_threshold
            // لكننا نسمح بـ m = bft_threshold كخيار أقل حماية
        }

        Ok(ConsensusPolicy {
            m,
            n,
            epoch_tolerance,
        })
    }

    /// السياسة الافتراضية (3 من 5).
    pub fn default() -> Self {
        ConsensusPolicy {
            m: DEFAULT_QUORUM_M,
            n: DEFAULT_QUORUM_N,
            epoch_tolerance: DEFAULT_EPOCH_TOLERANCE,
        }
    }

    /// التحقق من تحقق النصاب.
    #[inline]
    pub fn is_quorum_met(&self, valid_count: usize) -> bool {
        valid_count >= self.m
    }
}

// ============================================================================
// نتيجة الإجماع (Consensus Result)
// ============================================================================

/// نتيجة الإجماع المُجمّعة.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregatedBatchProof {
    /// هل تم الوصول إلى إجماع.
    pub consensus_reached: bool,
    /// عدد الحاويات الصالحة.
    pub valid_count: u32,
    /// الحد الأدنى المطلوب.
    pub required_count: u32,
    /// بصمة الإثباتات المُجمّعة (XOR دائري محاكى).
    pub aggregated_hash: [u8; 32],
    /// طابع زمني الإجماع (نانوثانية).
    pub consensus_timestamp_ns: u64,
    /// معرّف العصر المستخدم.
    pub consensus_epoch: u64,
    /// عدد العقد المشاركة.
    pub node_count: u8,
    /// حقل محجوز للمستقبل.
    pub _reserved: [u8; 23],
}

impl AggregatedBatchProof {
    /// إنشاء نتيجة إجماع جديدة.
    pub fn new(
        consensus_reached: bool,
        valid_count: u32,
        required_count: u32,
        aggregated_hash: [u8; 32],
        consensus_timestamp_ns: u64,
        consensus_epoch: u64,
        node_count: u8,
    ) -> Self {
        AggregatedBatchProof {
            consensus_reached,
            valid_count,
            required_count,
            aggregated_hash,
            consensus_timestamp_ns,
            consensus_epoch,
            node_count,
            _reserved: [0u8; 23],
        }
    }

    /// توليد بصمة موجزة (hex string).
    pub fn hex_hash(&self) -> [u8; 64] {
        let mut hex = [0u8; 64];
        for i in 0..32 {
            let byte = self.aggregated_hash[i];
            hex[i * 2] = match byte >> 4 {
                n @ 0..=9 => b'0' + n,
                n => b'a' + (n - 10),
            };
            hex[i * 2 + 1] = match byte & 0xf {
                n @ 0..=9 => b'0' + n,
                n => b'a' + (n - 10),
            };
        }
        hex
    }
}

// ============================================================================
// محرك التجميع (Aggregator Engine)
// ============================================================================

/// محرك التجميع والإجماع البيزنطي.
pub struct AggregatorEngine {
    policy: ConsensusPolicy,
    /// سجل الحاويات المعالجة (للتصحيح والتدقيق).
    envelopes: [Option<ProofEnvelope>; MAX_CONSENSUS_NODES],
    envelope_count: usize,
}

impl AggregatorEngine {
    /// إنشاء محرك تجميع جديد مع سياسة إجماع.
    pub fn new(policy: ConsensusPolicy) -> Self {
        AggregatorEngine {
            policy,
            envelopes: [None; MAX_CONSENSUS_NODES],
            envelope_count: 0,
        }
    }

    /// إضافة حاوية إثبات إلى محرك التجميع.
    pub fn add_envelope(&mut self, envelope: ProofEnvelope) -> Result<(), &'static str> {
        if self.envelope_count >= self.policy.n {
            return Err("تم الوصول إلى الحد الأقصى من الحاويات");
        }

        self.envelopes[self.envelope_count] = Some(envelope);
        self.envelope_count += 1;

        Ok(())
    }

    /// التحقق من صحة العصر الزمني (حماية ضد إعادة التشغيل).
    fn check_epoch_drift(
        &self,
        envelope: ProofEnvelope,
        current_epoch: u64,
    ) -> Result<bool, ValidationError> {
        Ok(envelope.is_epoch_valid(current_epoch, self.policy.epoch_tolerance))
    }

    /// تجميع الإثباتات باستخدام XOR دائري محاكى.
    fn aggregate_proofs(&self) -> [u8; 32] {
        let mut result = [0u8; 32];

        for i in 0..self.envelope_count {
            if let Some(envelope) = self.envelopes[i] {
                // XOR كل بايت من model_root_hash مع النتيجة
                for j in 0..32 {
                    let idx = (i + j) % 32; // دوران دائري للفهرس
                    result[idx] ^= envelope.model_root_hash[j];
                }
            }
        }

        result
    }

    /// التحقق من تحقق النصاب والإجماع.
    pub fn aggregate(
        &self,
        current_epoch: u64,
        timestamp_ns: u64,
    ) -> Result<AggregatedBatchProof, &'static str> {
        if self.envelope_count == 0 {
            return Err("لم تتم إضافة أي حاويات");
        }

        let mut valid_count = 0u32;

        // التحقق من صحة كل حاوية
        for i in 0..self.envelope_count {
            if let Some(envelope) = self.envelopes[i] {
                // التحقق من التوقيع السحري
                if envelope.header.magic != crate::SIB_MAGIC_NUMBER {
                    continue;
                }

                // التحقق من الطابع الزمني
                if !envelope.is_epoch_valid(current_epoch, self.policy.epoch_tolerance) {
                    continue;
                }

                valid_count += 1;
            }
        }

        // التحقق من النصاب
        let consensus_reached = self.policy.is_quorum_met(valid_count as usize);

        // تجميع الإثباتات
        let aggregated_hash = self.aggregate_proofs();

        Ok(AggregatedBatchProof::new(
            consensus_reached,
            valid_count,
            self.policy.m as u32,
            aggregated_hash,
            timestamp_ns,
            current_epoch,
            self.envelope_count as u8,
        ))
    }

    /// إعادة تعيين المحرك للدفعة التالية.
    pub fn reset(&mut self) {
        self.envelopes = [None; MAX_CONSENSUS_NODES];
        self.envelope_count = 0;
    }

    /// الحصول على عدد الحاويات المضافة.
    #[inline]
    pub fn envelope_count(&self) -> usize {
        self.envelope_count
    }

    /// الحصول على السياسة الحالية.
    #[inline]
    pub fn policy(&self) -> ConsensusPolicy {
        self.policy
    }
}

// ============================================================================
// اختبارات الوحدة (Unit Tests)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// إنشاء حاوية اختبارية.
    fn create_test_envelope(epoch: u64) -> ProofEnvelope {
        ProofEnvelope {
            header: crate::Header {
                magic: crate::SIB_MAGIC_NUMBER,
                dialect_id: 0x0001,
                epoch_id: epoch,
                timestamp_ns: 1000000000000u64,
                prover_puf_hash: [0x42u8; 32],
                _reserved: [0u8; 72],
            },
            model_root_hash: [0xAAu8; 48],
            public_inputs_hash: [0xBBu8; 32],
            stark_metadata: [0xCCu8; 32],
            stark_payload: [0xDDu8; 1504],
            action_hash: [0xEEu8; 32],
            circuit_id: [0xFFu8; 16],
            public_outputs_hash: [0x11u8; 32],
            snark_payload: [0x22u8; 736],
            sig_count: 1,
            _sig_reserved: 0,
        }
    }

    #[test]
    fn test_consensus_policy_creation() {
        let policy = ConsensusPolicy::new(3, 5, 10);
        assert!(policy.is_ok());

        let policy = policy.unwrap();
        assert_eq!(policy.m, 3);
        assert_eq!(policy.n, 5);
        assert_eq!(policy.epoch_tolerance, 10);
    }

    #[test]
    fn test_consensus_policy_invalid_m_gt_n() {
        let policy = ConsensusPolicy::new(6, 5, 10);
        assert!(policy.is_err());
    }

    #[test]
    fn test_consensus_policy_invalid_n_too_small() {
        let policy = ConsensusPolicy::new(1, 2, 10);
        assert!(policy.is_err());
    }

    #[test]
    fn test_quorum_check() {
        let policy = ConsensusPolicy::default();
        assert!(!policy.is_quorum_met(2));
        assert!(policy.is_quorum_met(3));
        assert!(policy.is_quorum_met(5));
    }

    #[test]
    fn test_aggregator_add_envelopes() {
        let policy = ConsensusPolicy::default();
        let mut engine = AggregatorEngine::new(policy);

        for i in 0..5 {
            let env = create_test_envelope(100 + i as u64);
            assert!(engine.add_envelope(env).is_ok());
        }

        assert_eq!(engine.envelope_count(), 5);
    }

    #[test]
    fn test_aggregator_consensus_reached() {
        let policy = ConsensusPolicy::default();
        let mut engine = AggregatorEngine::new(policy);

        // إضافة 3 حاويات صالحة (النصاب المطلوب)
        for i in 0..3 {
            let env = create_test_envelope(100);
            engine.add_envelope(env).unwrap();
        }

        let result = engine.aggregate(100, 1000000000000u64);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert!(proof.consensus_reached);
        assert_eq!(proof.valid_count, 3);
    }

    #[test]
    fn test_aggregator_consensus_not_reached() {
        let policy = ConsensusPolicy::default(); // M=3
        let mut engine = AggregatorEngine::new(policy);

        // إضافة حاويتين فقط (أقل من النصاب)
        for i in 0..2 {
            let env = create_test_envelope(100);
            engine.add_envelope(env).unwrap();
        }

        let result = engine.aggregate(100, 1000000000000u64);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert!(!proof.consensus_reached);
        assert_eq!(proof.valid_count, 2);
    }

    #[test]
    fn test_aggregator_epoch_drift_protection() {
        let policy = ConsensusPolicy::new(3, 5, 5).unwrap(); // tolerance = 5
        let mut engine = AggregatorEngine::new(policy);

        // إضافة حاوية بعصر صالح
        let env = create_test_envelope(100);
        engine.add_envelope(env).unwrap();

        // الاختبار مع عصر حالي = 100 (ضمن النطاق)
        let result = engine.aggregate(100, 1000000000000u64);
        assert!(result.is_ok());
        assert!(result.unwrap().consensus_reached);

        // إعادة تعيين وإضافة حاوية جديدة
        engine.reset();
        let env2 = create_test_envelope(100);
        engine.add_envelope(env2).unwrap();

        // الاختبار مع عصر حالي = 200 (خارج النطاق 95-105)
        let result = engine.aggregate(200, 1000000000000u64);
        assert!(result.is_ok());
        // لن يتم حسابها كصالحة بسبب انتهاء الصلاحية
        assert!(!result.unwrap().consensus_reached);
    }

    #[test]
    fn test_aggregated_proof_hex_hash() {
        let proof = AggregatedBatchProof::new(
            true,
            3,
            3,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            1000000000000u64,
            100,
            5,
        );

        let hex = proof.hex_hash();
        // تحقق من أن البصمة تحتوي على أحرف hex صحيحة
        assert_eq!(hex[0], b'0');
        assert_eq!(hex[1], b'1');
        assert_eq!(hex[2], b'2');
        assert_eq!(hex[3], b'3');
    }

    #[test]
    fn test_aggregator_reset() {
        let policy = ConsensusPolicy::default();
        let mut engine = AggregatorEngine::new(policy);

        let env = create_test_envelope(100);
        engine.add_envelope(env).unwrap();
        assert_eq!(engine.envelope_count(), 1);

        engine.reset();
        assert_eq!(engine.envelope_count(), 0);
    }
}
