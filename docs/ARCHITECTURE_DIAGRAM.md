# Architecture Diagram

> **Project:** veil7  
> **Version:** 1.0  
> **Last Updated:** 2026-06-15  
> **Status:** Production-Ready

---

## Table of Contents

1. [Overall Architecture](#1-overall-architecture)
2. [Data Flow Diagram](#2-data-flow-diagram)
3. [Component Interaction](#3-component-interaction)
4. [Trust Boundaries](#4-trust-boundaries)
5. [Attack Surfaces](#5-attack-surfaces)
6. [Layer-by-Layer Breakdown](#6-layer-by-layer-breakdown)
7. [Security Properties](#7-security-properties)

---

## 1. Overall Architecture

### High-Level Architecture Diagram

```mermaid
graph TB
    subgraph "Input Layer"
        A[Claim Input]
        B[Entropy Sources]
    end
    
    subgraph "veil7 Core Engine"
        subgraph "L0: Memory Protection"
            L0_1[mlock/mlockall]
            L0_2[Volatile Zeroization]
            L0_3[Compiler Fences]
        end
        
        subgraph "L1: Entropy Collection"
            L1_1[8 Hardware Sources]
            L1_2[4 Software Sources]
            L1_3[12-Round SHAKE256 Mixing]
            L1_4[Health Monitoring]
        end
        
        subgraph "L2: Key Generation"
            L2_1[ML-KEM-768 Keys]
            L2_2[ML-DSA-65 Keys]
            L2_3[libcrux Verification]
        end
        
        subgraph "L3: Commitment"
            L3_1[SHAKE256 Hash]
            L3_2[Domain Separation]
            L3_3[Fiat-Shamir Transcript]
        end
        
        subgraph "L4: Proof Generation"
            L4_1[ML-DSA-65 Signature]
            L4_2[KEM Encapsulation]
            L4_3[Hedged Signing]
        end
        
        subgraph "L5: Verification"
            L5_1[Signature Verification]
            L5_2[KEM Round-Trip]
            L5_3[Constant-Time Checks]
        end
        
        subgraph "L6: Zeroization"
            L6_1[Volatile Writes]
            L6_2[Compiler Fences]
            L6_3[RAII Cleanup]
        end
        
        subgraph "L7: Transcript Emission"
            L7_1[Verdict Construction]
            L7_2[Transcript Hash]
            L7_3[Zero Metadata]
        end
    end
    
    subgraph "Output Layer"
        Z[Verdict Output]
    end
    
    A --> L0_1
    B --> L1_1
    L0_1 --> L1_3
    L1_3 --> L2_1
    L2_1 --> L3_1
    L3_1 --> L4_1
    L4_1 --> L5_1
    L5_1 --> L6_1
    L6_1 --> L7_1
    L7_1 --> Z
```

### System Architecture Overview

```mermaid
graph LR
    subgraph "External World"
        User[User/Application]
        Entropy[Entropy Sources]
    end
    
    subgraph "veil7 Engine"
        Core[Core Engine<br/>7-Layer Pipeline]
        Memory[Memory Manager<br/>L0 Protection]
        Crypto[Crypto Backend<br/>libcrux]
    end
    
    subgraph "Output"
        Verdict[Verdict<br/>33 bytes]
    end
    
    User -->|Claim| Core
    Entropy -->|Randomness| Core
    Core -->|Keys| Crypto
    Crypto -->|Verification| Core
    Memory -->|Protection| Core
    Core -->|Verdict| Verdict
    Verdict --> User
```

---

## 2. Data Flow Diagram

### End-to-End Data Flow

```mermaid
sequenceDiagram
    participant U as User
    participant L0 as L0: Memory
    participant L1 as L1: Entropy
    participant L2 as L2: KeyGen
    participant L3 as L3: Commit
    participant L4 as L4: Prove
    participant L5 as L5: Verify
    participant L6 as L6: Zeroize
    participant L7 as L7: Emit
    
    U->>L0: Claim (arbitrary bytes)
    L0->>L0: mlock() memory
    L0->>L1: Protected claim
    
    L1->>L1: Collect 12 entropy sources
    L1->>L1: 12-round SHAKE256 mixing
    L1->>L1: Health checks (RCT + APT)
    L1->>L2: 64-byte master seed
    
    L2->>L2: Derive ML-KEM-768 keys
    L2->>L2: Derive ML-DSA-65 keys
    L2->>L3: Ephemeral keypair
    
    L3->>L3: SHAKE256(claim || keys)
    L3->>L3: Domain separation
    L3->>L4: 32-byte commitment
    
    L4->>L4: Sign commitment (ML-DSA-65)
    L4->>L4: KEM encapsulation
    L4->>L5: Signature + ciphertext
    
    L5->>L5: Verify signature (CT)
    L5->>L5: KEM round-trip (CT)
    L5->>L5: Combine: sig_ok & kem_ok
    L5->>L6: Choice (0 or 1)
    
    L6->>L6: Zeroize all keys (volatile)
    L6->>L6: Compiler fence (SeqCst)
    L6->>L7: Zeroized memory
    
    L7->>L7: Construct Verdict
    L7->>L7: Transcript hash
    L7->>U: Verdict (33 bytes)
    
    L6->>L0: munlock() memory
```

### Detailed Data Flow per Layer

```mermaid
flowchart TB
    subgraph Input
        Claim[Claim: arbitrary bytes]
        Entropy[Entropy: 12 sources]
    end
    
    subgraph "L0: Memory Protection"
        L0_in[Input: claim]
        L0_lock[mlock memory]
        L0_out[Protected claim]
        L0_in --> L0_lock --> L0_out
    end
    
    subgraph "L1: Entropy Collection"
        L1_in[Input: 12 sources]
        L1_mix[12-round SHAKE256]
        L1_health[Health checks]
        L1_out[64-byte seed]
        L1_in --> L1_mix --> L1_health --> L1_out
    end
    
    subgraph "L2: Key Generation"
        L2_in[Input: 64-byte seed]
        L2_kem[ML-KEM-768 keys]
        L2_dsa[ML-DSA-65 keys]
        L2_out[Ephemeral keypair]
        L2_in --> L2_kem --> L2_dsa --> L2_out
    end
    
    subgraph "L3: Commitment"
        L3_in[Input: claim + keys]
        L3_hash[SHAKE256 hash]
        L3_domain[Domain separation]
        L3_out[32-byte commitment]
        L3_in --> L3_hash --> L3_domain --> L3_out
    end
    
    subgraph "L4: Proof Generation"
        L4_in[Input: commitment + keys]
        L4_sig[ML-DSA-65 signature]
        L4_kem[KEM encapsulation]
        L4_out[Signature + ciphertext]
        L4_in --> L4_sig --> L4_kem --> L4_out
    end
    
    subgraph "L5: Verification"
        L5_in[Input: signature + ciphertext]
        L5_sig[Signature verification]
        L5_kem[KEM round-trip]
        L5_combine[Combine: sig_ok & kem_ok]
        L5_out[Choice: 0 or 1]
        L5_in --> L5_sig --> L5_kem --> L5_combine --> L5_out
    end
    
    subgraph "L6: Zeroization"
        L6_in[Input: all keys]
        L6_volatile[Volatile writes]
        L6_fence[Compiler fence]
        L6_out[Zeroized memory]
        L6_in --> L6_volatile --> L6_fence --> L6_out
    end
    
    subgraph "L7: Transcript Emission"
        L7_in[Input: Choice + transcript]
        L7_verdict[Verdict construction]
        L7_hash[Transcript hash]
        L7_out[Verdict: 33 bytes]
        L7_in --> L7_verdict --> L7_hash --> L7_out
    end
    
    Claim --> L0_in
    Entropy --> L1_in
    L0_out --> L1_in
    L1_out --> L2_in
    L2_out --> L3_in
    L3_out --> L4_in
    L4_out --> L5_in
    L5_out --> L6_in
    L6_out --> L7_in
```

---

## 3. Component Interaction

### Component Interaction Diagram

```mermaid
graph TB
    subgraph "Core Components"
        Engine[veil7 Engine]
        Memory[Memory Manager]
        Crypto[Crypto Backend]
        Entropy[Entropy Manager]
    end
    
    subgraph "Layer Components"
        L0[L0: Memory Protection]
        L1[L1: Entropy Collection]
        L2[L2: Key Generation]
        L3[L3: Commitment]
        L4[L4: Proof Generation]
        L5[L5: Verification]
        L6[L6: Zeroization]
        L7[L7: Transcript Emission]
    end
    
    subgraph "External Dependencies"
        libcrux[libcrux]
        subtle[subtle]
        sha3[sha3]
        OS[OS Kernel]
    end
    
    Engine --> L0
    Engine --> L1
    Engine --> L2
    Engine --> L3
    Engine --> L4
    Engine --> L5
    Engine --> L6
    Engine --> L7
    
    L0 --> Memory
    L1 --> Entropy
    L2 --> Crypto
    L3 --> Crypto
    L4 --> Crypto
    L5 --> Crypto
    
    Memory --> OS
    Entropy --> OS
    Crypto --> libcrux
    Crypto --> subtle
    Crypto --> sha3
```

### API Interaction Flow

```mermaid
sequenceDiagram
    participant API as Public API
    participant Engine as veil7 Engine
    participant L0 as L0
    participant L1 as L1
    participant L2 as L2
    participant L3 as L3
    participant L4 as L4
    participant L5 as L5
    participant L6 as L6
    participant L7 as L7
    
    API->>Engine: verify_once(claim)
    
    Engine->>L0: protect_memory(claim)
    L0-->>Engine: protected_claim
    
    Engine->>L1: collect_entropy()
    L1-->>Engine: master_seed (64 bytes)
    
    Engine->>L2: generate_keys(seed)
    L2-->>Engine: ephemeral_keypair
    
    Engine->>L3: commit(claim, keys)
    L3-->>Engine: commitment (32 bytes)
    
    Engine->>L4: prove(commitment, keys)
    L4-->>Engine: proof (signature + ciphertext)
    
    Engine->>L5: verify(proof, keys)
    L5-->>Engine: verdict_choice (0 or 1)
    
    Engine->>L6: zeroize(keys)
    L6-->>Engine: zeroized
    
    Engine->>L7: emit(verdict_choice, transcript)
    L7-->>Engine: verdict (33 bytes)
    
    Engine-->>API: Verdict
```

---

## 4. Trust Boundaries

### Trust Boundary Diagram

```mermaid
graph TB
    subgraph "UNTRUSTED ZONE"
        User[User Input<br/>UNTRUSTED]
        ExternalEntropy[External Entropy<br/>PARTIALLY TRUSTED]
    end
    
    subgraph "TRUSTED ZONE 1: Memory Protection"
        L0[L0: Memory Protection<br/>TRUSTED]
    end
    
    subgraph "TRUSTED ZONE 2: Entropy Collection"
        L1[L1: Entropy Collection<br/>TRUSTED]
    end
    
    subgraph "TRUSTED ZONE 3: Cryptographic Operations"
        L2[L2: Key Generation<br/>HIGHLY TRUSTED]
        L3[L3: Commitment<br/>HIGHLY TRUSTED]
        L4[L4: Proof Generation<br/>HIGHLY TRUSTED]
        L5[L5: Verification<br/>HIGHLY TRUSTED]
    end
    
    subgraph "TRUSTED ZONE 4: Zeroization"
        L6[L6: Zeroization<br/>CRITICAL TRUST]
    end
    
    subgraph "TRUSTED ZONE 5: Output"
        L7[L7: Transcript Emission<br/>TRUSTED]
    end
    
    subgraph "UNTRUSTED ZONE"
        Output[Verdict Output<br/>PUBLIC DATA]
    end
    
    User -->|Crosses TB1| L0
    ExternalEntropy -->|Crosses TB2| L1
    L0 -->|Crosses TB3| L1
    L1 -->|Crosses TB4| L2
    L5 -->|Crosses TB5| L6
    L6 -->|Crosses TB6| L7
    L7 -->|Crosses TB7| Output
```

### Trust Level per Layer

```mermaid
graph LR
    subgraph "Trust Levels"
        T1[TRUST LEVEL 1<br/>Memory Protection]
        T2[TRUST LEVEL 2<br/>Entropy Collection]
        T3[TRUST LEVEL 3<br/>Cryptographic Operations]
        T4[TRUST LEVEL 4<br/>Zeroization]
        T5[TRUST LEVEL 5<br/>Output Emission]
    end
    
    L0[L0] --> T1
    L1[L1] --> T2
    L2[L2] --> T3
    L3[L3] --> T3
    L4[L4] --> T3
    L5[L5] --> T3
    L6[L6] --> T4
    L7[L7] --> T5
```

---

## 5. Attack Surfaces

### Attack Surface Diagram

```mermaid
graph TB
    subgraph "Attack Surfaces"
        AS1[AS1: Input Validation<br/>Claim Input]
        AS2[AS2: Entropy Sources<br/>Random Number Generation]
        AS3[AS3: Memory Protection<br/>Memory Access]
        AS4[AS4: Cryptographic Operations<br/>Side-Channel Attacks]
        AS5[AS5: Timing Attacks<br/>Execution Time]
        AS6[AS6: Zeroization<br/>Memory Remanence]
        AS7[AS7: Output<br/>Metadata Leakage]
    end
    
    subgraph "Mitigations"
        M1[M1: Input Sanitization]
        M2[M2: 12 Entropy Sources + Health Checks]
        M3[M3: mlock + Volatile Writes]
        M4[M4: libcrux + Constant-Time]
        M5[M5: Constant-Time Operations]
        M6[M6: Volatile Writes + Compiler Fences]
        M7[M7: Zero Metadata Design]
    end
    
    AS1 --> M1
    AS2 --> M2
    AS3 --> M3
    AS4 --> M4
    AS5 --> M5
    AS6 --> M6
    AS7 --> M7
```

### Attack Vector Mitigation Matrix

```mermaid
graph LR
    subgraph "Attack Vectors"
        AV1[Timing Attacks]
        AV2[Side-Channel Attacks]
        AV3[Memory Attacks]
        AV4[Entropy Attacks]
        AV5[Replay Attacks]
        AV6[Metadata Attacks]
    end
    
    subgraph "Mitigations by Layer"
        L0_M[L0: mlock + volatile]
        L1_M[L1: 12 sources + health]
        L2_M[L2: libcrux CT]
        L3_M[L3: domain separation]
        L4_M[L4: hedged signing]
        L5_M[L5: CT verification]
        L6_M[L6: volatile + fence]
        L7_M[L7: zero metadata]
    end
    
    AV1 --> L2_M
    AV1 --> L5_M
    AV2 --> L2_M
    AV2 --> L4_M
    AV2 --> L5_M
    AV3 --> L0_M
    AV3 --> L6_M
    AV4 --> L1_M
    AV5 --> L3_M
    AV5 --> L4_M
    AV6 --> L7_M
```

---

## 6. Layer-by-Layer Breakdown

### Layer Architecture Overview

```mermaid
graph TB
    subgraph "Layer 0: Memory Protection"
        L0_1[mlock/mlockall]
        L0_2[Volatile Zeroization]
        L0_3[Compiler Fences]
        L0_4[RAII Wrapper]
    end
    
    subgraph "Layer 1: Entropy Collection"
        L1_1[8 Hardware Sources]
        L1_2[4 Software Sources]
        L1_3[12-Round Mixing]
        L1_4[Health Monitoring]
    end
    
    subgraph "Layer 2: Key Generation"
        L2_1[ML-KEM-768]
        L2_2[ML-DSA-65]
        L2_3[libcrux Backend]
    end
    
    subgraph "Layer 3: Commitment"
        L3_1[SHAKE256 Hash]
        L3_2[Domain Separation]
        L3_3[Fiat-Shamir]
    end
    
    subgraph "Layer 4: Proof Generation"
        L4_1[ML-DSA Signing]
        L4_2[KEM Encapsulation]
        L4_3[Hedged Signing]
    end
    
    subgraph "Layer 5: Verification"
        L5_1[Signature Verify]
        L5_2[KEM Round-Trip]
        L5_3[Constant-Time]
    end
    
    subgraph "Layer 6: Zeroization"
        L6_1[Volatile Writes]
        L6_2[Compiler Fences]
        L6_3[RAII Cleanup]
    end
    
    subgraph "Layer 7: Transcript Emission"
        L7_1[Verdict Construction]
        L7_2[Transcript Hash]
        L7_3[Zero Metadata]
    end
```

### Layer Dependencies

```mermaid
graph LR
    L0[L0: Memory] --> L1[L1: Entropy]
    L1 --> L2[L2: KeyGen]
    L2 --> L3[L3: Commit]
    L3 --> L4[L4: Prove]
    L4 --> L5[L5: Verify]
    L5 --> L6[L6: Zeroize]
    L6 --> L7[L7: Emit]
    
    L0 --> L2
    L0 --> L6
    L1 --> L2
    L2 --> L4
    L2 --> L5
```

---

## 7. Security Properties

### Security Properties per Layer

```mermaid
graph TB
    subgraph "Security Properties"
        SP1[Memory Protection]
        SP2[Entropy Quality]
        SP3[Key Security]
        SP4[Commitment Binding]
        SP5[Proof Soundness]
        SP6[Verification Correctness]
        SP7[Complete Zeroization]
        SP8[Zero Metadata]
    end
    
    L0[L0] --> SP1
    L1[L1] --> SP2
    L2[L2] --> SP3
    L3[L3] --> SP4
    L4[L4] --> SP5
    L5[L5] --> SP6
    L6[L6] --> SP7
    L7[L7] --> SP8
```

### Security Property Verification

```mermaid
graph LR
    subgraph "Verification Methods"
        V1[Formal Verification]
        V2[Unit Tests]
        V3[Integration Tests]
        V4[Property Tests]
        V5[Security Audit]
    end
    
    SP1 --> V1
    SP1 --> V2
    SP2 --> V2
    SP2 --> V3
    SP3 --> V1
    SP3 --> V2
    SP4 --> V2
    SP4 --> V4
    SP5 --> V1
    SP5 --> V2
    SP6 --> V2
    SP6 --> V3
    SP7 --> V1
    SP7 --> V2
    SP8 --> V2
    SP8 --> V5
```

---

## Appendix A: Component Details

### L0: Memory Protection Components

| Component | Purpose | Implementation |
|-----------|---------|----------------|
| `mlock()` | Lock memory pages | POSIX system call |
| `mlockall()` | Lock all memory | POSIX system call |
| `write_volatile()` | Prevent optimization | Rust core::ptr |
| `compiler_fence()` | Prevent reordering | Rust core::sync::atomic |
| `Zeroizing<T>` | RAII wrapper | Custom implementation |

### L1: Entropy Collection Components

| Component | Purpose | Implementation |
|-----------|---------|----------------|
| Hardware sources | High-quality randomness | RDRAND, RDSEED, etc. |
| Software sources | Fallback entropy | Timing, memory layout |
| SHAKE256 mixing | Entropy conditioning | libcrux-sha3 |
| RCT test | Detect stuck sources | NIST SP 800-90B |
| APT test | Detect biased sources | NIST SP 800-90B |

### L2: Key Generation Components

| Component | Purpose | Implementation |
|-----------|---------|----------------|
| ML-KEM-768 | Key encapsulation | libcrux-ml-kem |
| ML-DSA-65 | Digital signatures | libcrux-ml-dsa |
| Key derivation | Seed expansion | SHAKE256 |
| Constant-time | Timing protection | libcrux CT |

### L3: Commitment Components

| Component | Purpose | Implementation |
|-----------|---------|----------------|
| SHAKE256 hash | Commitment function | libcrux-sha3 |
| Domain separation | Prevent cross-layer | Custom domain tags |
| Fiat-Shamir | Non-interactive proof | Transcript accumulator |

### L4: Proof Generation Components

| Component | Purpose | Implementation |
|-----------|---------|----------------|
| ML-DSA signing | Signature generation | libcrux-ml-dsa |
| KEM encapsulation | Key encapsulation | libcrux-ml-kem |
| Hedged signing | Nonce protection | H(sk \|\| msg \|\| random) |
| Constant-time | Timing protection | libcrux CT |

### L5: Verification Components

| Component | Purpose | Implementation |
|-----------|---------|----------------|
| Signature verify | Signature verification | libcrux-ml-dsa |
| KEM round-trip | Key consistency | libcrux-ml-kem |
| Constant-time | Timing protection | subtle::Choice |
| Dual checks | Defense-in-depth | sig_ok & kem_ok |

### L6: Zeroization Components

| Component | Purpose | Implementation |
|-----------|---------|----------------|
| Volatile writes | Prevent optimization | Rust core::ptr |
| Compiler fences | Prevent reordering | Rust core::sync::atomic |
| RAII cleanup | Automatic cleanup | Custom Drop impl |
| Multi-pass | Defense-in-depth | 4-layer protection |

### L7: Transcript Emission Components

| Component | Purpose | Implementation |
|-----------|---------|----------------|
| Verdict construction | Output formatting | Custom Verdict struct |
| Transcript hash | Binding proof | SHAKE256 |
| Zero metadata | Privacy protection | 33 bytes only |

---

## Appendix B: Data Flow Details

### Input Data

| Data | Size | Source | Trust Level |
|------|------|--------|-------------|
| Claim | Arbitrary | User | UNTRUSTED |
| Entropy | 12 sources | Hardware + Software | PARTIALLY TRUSTED |

### Intermediate Data

| Data | Size | Layer | Trust Level |
|------|------|-------|-------------|
| Protected claim | Arbitrary | L0 | TRUSTED |
| Master seed | 64 bytes | L1 | TRUSTED |
| Ephemeral keypair | Variable | L2 | HIGHLY TRUSTED |
| Commitment | 32 bytes | L3 | HIGHLY TRUSTED |
| Signature + ciphertext | Variable | L4 | HIGHLY TRUSTED |
| Verdict choice | 1 bit | L5 | HIGHLY TRUSTED |
| Zeroized memory | N/A | L6 | CRITICAL |

### Output Data

| Data | Size | Layer | Trust Level |
|------|------|-------|-------------|
| Verdict | 33 bytes | L7 | PUBLIC DATA |

---

*End of ARCHITECTURE_DIAGRAM.md*

*Document generated: 2026-06-15*  
*Version: 1.0*
