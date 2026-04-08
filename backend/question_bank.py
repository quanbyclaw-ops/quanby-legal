"""
question_bank.py — Quanby Legal ENP Certification Question Bank
Questions are randomized per session. 30 questions per category,
15 drawn randomly per test. Never static.

Security design:
- get_randomized_test() returns (client_questions, answer_key) as a tuple
- client_questions: list of dicts WITHOUT 'answer' field — safe to send to browser
- answer_key: {question_id: correct_answer_text} — stays server-side ONLY
- answer_key stores full answer TEXT (not letter) so shuffling never corrupts correctness
"""

import random
from typing import List

# ─── ATTORNEY QUESTIONS (Philippine ENP Certification) ─────────────────────

ATTORNEY_QUESTIONS = [
    {
        "id": "atty_001",
        "question": "Under A.M. No. 24-10-14-SC, what is the primary difference between In-Person Electronic Notarization (IEN) and Remote Electronic Notarization (REN)?",
        "choices": [
            "A. IEN requires a physical notarial seal; REN does not",
            "B. IEN requires the principal to be physically present; REN allows the principal to appear via audiovisual communication technology",
            "C. IEN is available only in Metro Manila; REN is for provinces",
            "D. There is no difference — both are considered in-person"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_002",
        "question": "Which Republic Act governs the legal validity of electronic signatures in the Philippines?",
        "choices": [
            "A. RA 10175 — Cybercrime Prevention Act",
            "B. RA 10173 — Data Privacy Act",
            "C. RA 8792 — Electronic Commerce Act",
            "D. RA 9160 — Anti-Money Laundering Act"
        ],
        "answer": "C",
        "category": "Legal Framework"
    },
    {
        "id": "atty_003",
        "question": "Under the 2004 Rules on Notarial Practice (as extended by A.M. No. 24-10-14-SC), a notary public must ensure the principal is NOT:",
        "choices": [
            "A. Personally known or identified through competent evidence",
            "B. Acting freely and voluntarily",
            "C. Under duress, influence, or incapacity",
            "D. Present in another country"
        ],
        "answer": "C",
        "category": "Notarial Practice"
    },
    {
        "id": "atty_004",
        "question": "What is the maximum validity period of a notarial commission in the Philippines?",
        "choices": [
            "A. One (1) year",
            "B. Two (2) years",
            "C. Three (3) years",
            "D. Five (5) years"
        ],
        "answer": "B",
        "category": "Notarial Practice"
    },
    {
        "id": "atty_005",
        "question": "Under RA 10173 (Data Privacy Act), personal data collected during e-notarization must be:",
        "choices": [
            "A. Shared with all law enforcement agencies without restriction",
            "B. Retained indefinitely for audit purposes",
            "C. Processed lawfully, fairly, and for specified, explicit, and legitimate purposes",
            "D. Stored only in cloud services located outside the Philippines"
        ],
        "answer": "C",
        "category": "Data Privacy"
    },
    {
        "id": "atty_006",
        "question": "BSP Circular No. 944 specifically governs:",
        "choices": [
            "A. Electronic notarization procedures",
            "B. Electronic Know-Your-Customer (eKYC) standards for financial institutions",
            "C. Anti-money laundering reporting",
            "D. Corporate governance for banks"
        ],
        "answer": "B",
        "category": "Regulatory"
    },
    {
        "id": "atty_007",
        "question": "An Electronic Notary Public (ENP) may perform Remote Electronic Notarization (REN) for a principal located abroad ONLY IF:",
        "choices": [
            "A. The document is notarized under foreign law",
            "B. The principal is a Filipino citizen and the document is for use in the Philippines, subject to applicable rules",
            "C. A foreign notary co-signs the document",
            "D. REN is never allowed for principals located abroad"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_008",
        "question": "Under the Civil Code of the Philippines, which element is NOT required for a valid contract?",
        "choices": [
            "A. Consent of the contracting parties",
            "B. Object certain which is the subject matter",
            "C. Cause of the obligation",
            "D. Notarization of the document"
        ],
        "answer": "D",
        "category": "Civil Law"
    },
    {
        "id": "atty_009",
        "question": "Which court or body accredits Electronic Notarization Facilities (ENFs) in the Philippines?",
        "choices": [
            "A. Department of Justice (DOJ)",
            "B. Integrated Bar of the Philippines (IBP)",
            "C. Supreme Court of the Philippines",
            "D. Securities and Exchange Commission (SEC)"
        ],
        "answer": "C",
        "category": "ENP Rules"
    },
    {
        "id": "atty_010",
        "question": "A Deed of Absolute Sale must be notarized primarily because:",
        "choices": [
            "A. It is required by the Civil Code for all contracts",
            "B. It converts the document from a private to a public instrument, giving it evidentiary weight",
            "C. It ensures the buyer pays the correct taxes",
            "D. Banks require notarization for all real property transactions"
        ],
        "answer": "B",
        "category": "Legal Practice"
    },
    {
        "id": "atty_011",
        "question": "Under A.M. No. 24-10-14-SC, the electronic notarial register (e-register) must be maintained for a minimum of:",
        "choices": [
            "A. One (1) year",
            "B. Five (5) years",
            "C. Ten (10) years",
            "D. Permanently"
        ],
        "answer": "C",
        "category": "ENP Rules"
    },
    {
        "id": "atty_012",
        "question": "SEC Memorandum Circular No. 28-2020 primarily authorizes:",
        "choices": [
            "A. Online trading of securities",
            "B. Remote notarization for SEC filings",
            "C. Electronic signatures for banking transactions",
            "D. Digital incorporation of corporations"
        ],
        "answer": "B",
        "category": "Regulatory"
    },
    {
        "id": "atty_013",
        "question": "Under the Anti-Money Laundering Act (RA 9160, as amended), covered persons must report suspicious transactions to:",
        "choices": [
            "A. The National Privacy Commission (NPC)",
            "B. The Anti-Money Laundering Council (AMLC)",
            "C. The Bangko Sentral ng Pilipinas (BSP)",
            "D. The Department of Finance (DOF)"
        ],
        "answer": "B",
        "category": "Compliance"
    },
    {
        "id": "atty_014",
        "question": "In a contract of lease under Philippine law, the lessee's right to the property is BEST described as:",
        "choices": [
            "A. A real right enforceable against everyone",
            "B. A personal right enforceable only against the lessor",
            "C. An absolute right that cannot be extinguished",
            "D. A property right that passes to the lessee's heirs automatically"
        ],
        "answer": "B",
        "category": "Civil Law"
    },
    {
        "id": "atty_015",
        "question": "The DICT National PKI (PNPKI) issues digital certificates that serve as:",
        "choices": [
            "A. Proof of tax payment",
            "B. Government-grade identity verification for electronic signatures",
            "C. Business permits for ENFs",
            "D. Court clearances for notarized documents"
        ],
        "answer": "B",
        "category": "Technology"
    },
    {
        "id": "atty_016",
        "question": "Under A.M. No. 24-10-14-SC, which of the following is a MANDATORY requirement for all REN sessions?",
        "choices": [
            "A. The principal must use a desktop computer",
            "B. Both the ENP and principal must be recorded via audiovisual communication technology",
            "C. A witness must be physically present at the ENP's location",
            "D. The session must be conducted only during business hours"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_017",
        "question": "An acknowledgment in a notarial act means the principal declares before the notary that:",
        "choices": [
            "A. The document is legally binding on third parties",
            "B. The instrument is his/her free and voluntary act and deed",
            "C. All facts stated in the document are true",
            "D. No taxes are due on the transaction"
        ],
        "answer": "B",
        "category": "Notarial Practice"
    },
    {
        "id": "atty_018",
        "question": "Under Philippine law, a Special Power of Attorney (SPA) grants the attorney-in-fact authority to perform:",
        "choices": [
            "A. Any act on behalf of the principal",
            "B. Only acts specifically enumerated in the SPA",
            "C. Acts of strict ownership only",
            "D. Acts that generate income for the principal"
        ],
        "answer": "B",
        "category": "Civil Law"
    },
    {
        "id": "atty_019",
        "question": "The National Privacy Commission (NPC) requires organizations to designate a:",
        "choices": [
            "A. Chief Information Officer (CIO)",
            "B. Data Protection Officer (DPO)",
            "C. Privacy Compliance Auditor (PCA)",
            "D. Information Security Manager (ISM)"
        ],
        "answer": "B",
        "category": "Data Privacy"
    },
    {
        "id": "atty_020",
        "question": "In Philippine corporate law under RA 11232 (Revised Corporation Code), the minimum number of incorporators required to form a stock corporation is:",
        "choices": [
            "A. Five (5)",
            "B. Three (3)",
            "C. One (1)",
            "D. Two (2)"
        ],
        "answer": "C",
        "category": "Corporate Law"
    },
    {
        "id": "atty_021",
        "question": "A jurat in a notarial act requires the affiant to:",
        "choices": [
            "A. Simply present a valid ID",
            "B. Sign in the presence of the notary and swear/affirm the truth of the contents",
            "C. Pay the notarial fee before signing",
            "D. Have two witnesses present"
        ],
        "answer": "B",
        "category": "Notarial Practice"
    },
    {
        "id": "atty_022",
        "question": "Under RA 8792, an electronic document has the same legal effect as a paper document UNLESS:",
        "choices": [
            "A. It is stored in the cloud",
            "B. The law specifically requires a document to be in writing and excludes electronic form",
            "C. It is signed with a simple electronic signature",
            "D. It is transmitted via email"
        ],
        "answer": "B",
        "category": "Legal Framework"
    },
    {
        "id": "atty_023",
        "question": "Under A.M. No. 24-10-14-SC, which document CANNOT be e-notarized?",
        "choices": [
            "A. A Deed of Absolute Sale",
            "B. A Last Will and Testament",
            "C. A Contract of Lease",
            "D. A Special Power of Attorney"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_024",
        "question": "The blockchain audit trail in Quanby Legal ensures document integrity through:",
        "choices": [
            "A. Password protection",
            "B. Cryptographic hashing and immutable distributed ledger entries",
            "C. Physical storage in a secure vault",
            "D. Regular government audits"
        ],
        "answer": "B",
        "category": "Technology"
    },
    {
        "id": "atty_025",
        "question": "Under the Labor Code of the Philippines, regular employees may only be dismissed for:",
        "choices": [
            "A. Any reason at the employer's discretion",
            "B. Just causes or authorized causes, with due process",
            "C. Performance issues alone without prior notice",
            "D. End of project, without separation pay"
        ],
        "answer": "B",
        "category": "Labor Law"
    },
    {
        "id": "atty_026",
        "question": "For a Memorandum of Agreement (MOA) to be legally enforceable in the Philippines, it must have:",
        "choices": [
            "A. Notarization, consideration, and three witnesses",
            "B. Consent, object, and cause — the essential requisites of a valid contract",
            "C. A SEC-registered format and BIR stamp",
            "D. A government approval from the relevant agency"
        ],
        "answer": "B",
        "category": "Civil Law"
    },
    {
        "id": "atty_027",
        "question": "An ENP who performs notarial acts outside their authorized territorial jurisdiction may face:",
        "choices": [
            "A. A fine of ₱50,000",
            "B. Suspension or revocation of their notarial commission",
            "C. Criminal charges under the Cybercrime Prevention Act",
            "D. Loss of IBP membership only"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_028",
        "question": "Under RA 10173, the right of a data subject to request deletion of their personal data is known as the:",
        "choices": [
            "A. Right to access",
            "B. Right to erasure or blocking",
            "C. Right to portability",
            "D. Right to rectification"
        ],
        "answer": "B",
        "category": "Data Privacy"
    },
    {
        "id": "atty_029",
        "question": "An e-notarized Deed of Sale for real property in the Philippines must still be submitted to which agency for transfer of title?",
        "choices": [
            "A. Securities and Exchange Commission",
            "B. Bureau of Internal Revenue (BIR) for tax clearance, then Register of Deeds",
            "C. Department of Justice",
            "D. Local Government Unit (LGU) only"
        ],
        "answer": "B",
        "category": "Legal Practice"
    },
    {
        "id": "atty_030",
        "question": "Under A.M. No. 24-10-14-SC, an ENP must verify the identity of a remote principal using:",
        "choices": [
            "A. A simple photo ID sent via email",
            "B. Government-issued ID and liveness verification through audiovisual technology",
            "C. A witness attestation letter",
            "D. A barangay clearance"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    # ── NEW QUESTIONS: atty_031 to atty_050 ─────────────────────────────────
    {
        "id": "atty_031",
        "question": "Under A.M. No. 24-10-14-SC, which of the following is a ground for REVOCATION of an ENP's commission?",
        "choices": [
            "A. Performing more than 100 notarial acts in a month",
            "B. Gross misconduct, conviction of a crime involving moral turpitude, or violation of the Rules on ENP",
            "C. Failure to renew commission within 30 days of expiry",
            "D. Using a digital signature not issued by the Supreme Court"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_032",
        "question": "Under the 2004 Rules on Notarial Practice, a notary public is PROHIBITED from notarizing a document if:",
        "choices": [
            "A. The document was drafted by another attorney",
            "B. The notary is a party to the instrument or has a financial interest in the transaction",
            "C. The document is more than 10 pages long",
            "D. The principal is from a different city"
        ],
        "answer": "B",
        "category": "Notarial Practice"
    },
    {
        "id": "atty_033",
        "question": "The primary difference between a Jurat and an Acknowledgment is:",
        "choices": [
            "A. A Jurat requires payment of a higher notarial fee than an Acknowledgment",
            "B. In a Jurat, the affiant swears to the truth of the document's contents; in an Acknowledgment, the principal confirms it is their free and voluntary act",
            "C. An Acknowledgment requires two witnesses while a Jurat requires none",
            "D. A Jurat is used only for wills; an Acknowledgment is used for contracts"
        ],
        "answer": "B",
        "category": "Notarial Practice"
    },
    {
        "id": "atty_034",
        "question": "Under RA 8792 (Electronic Commerce Act), an electronic signature is legally binding when:",
        "choices": [
            "A. It is affixed using a government-approved hardware token only",
            "B. It is distinctively linked to the signatory, capable of identifying them, created under their sole control, and any alteration to the document is detectable",
            "C. It is notarized by an accredited ENP within 24 hours of signing",
            "D. It is registered with the SEC or DTI"
        ],
        "answer": "B",
        "category": "Legal Framework"
    },
    {
        "id": "atty_035",
        "question": "Under BSP Circular 944, which of the following is an acceptable method for eKYC identity verification?",
        "choices": [
            "A. Submission of a photocopy of any ID via ordinary mail",
            "B. Facial recognition with liveness detection matched against a government-issued ID",
            "C. A verbal confirmation of name and birthdate during a phone call",
            "D. Presentation of an employee ID from any private company"
        ],
        "answer": "B",
        "category": "Regulatory"
    },
    {
        "id": "atty_036",
        "question": "Under A.M. No. 24-10-14-SC, the ENP's electronic notarial register (e-register) must include:",
        "choices": [
            "A. Only the name of the principal and date of notarization",
            "B. Entry number, date and time, type of notarial act, name and ID of principal, description of document, and fee charged",
            "C. Only the document hash and digital certificate serial number",
            "D. The principal's full financial background and credit score"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_037",
        "question": "What is the minimum document retention period for electronic notarial certificates under A.M. No. 24-10-14-SC?",
        "choices": [
            "A. Three (3) years",
            "B. Ten (10) years",
            "C. Five (5) years",
            "D. Permanently"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_038",
        "question": "Under RA 10173 (Data Privacy Act), what is the required action when a personal data breach occurs that likely harms data subjects?",
        "choices": [
            "A. The organization may keep the breach confidential to avoid public panic",
            "B. Notify the National Privacy Commission (NPC) within 72 hours of discovery and inform affected data subjects",
            "C. File a criminal complaint with the NBI before notifying anyone",
            "D. Delete all affected data immediately to stop further harm"
        ],
        "answer": "B",
        "category": "Data Privacy"
    },
    {
        "id": "atty_039",
        "question": "When an ENP's notarial commission EXPIRES, they must:",
        "choices": [
            "A. Continue notarizing until a replacement ENP is appointed",
            "B. Immediately cease performing notarial acts and surrender or secure their notarial records pending renewal or transfer",
            "C. Only cease Remote Electronic Notarization but may continue In-Person Electronic Notarization",
            "D. Notify clients only if they have pending notarial acts"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_040",
        "question": "Under the 2004 Rules on Notarial Practice, which of the following constitutes COMPETENT EVIDENCE OF IDENTITY?",
        "choices": [
            "A. A printed screenshot of a social media profile",
            "B. At least one current government-issued ID with photograph and signature of the individual",
            "C. A barangay certification with the individual's description",
            "D. A sworn statement by two witnesses attesting to the person's identity"
        ],
        "answer": "B",
        "category": "Notarial Practice"
    },
    {
        "id": "atty_041",
        "question": "The Supreme Court accreditation requirement for ENP platforms primarily ensures that the platform:",
        "choices": [
            "A. Is built using only Philippine-made software",
            "B. Meets technical, security, and procedural standards set by the Court to protect the integrity of notarial acts",
            "C. Is majority-owned by Filipino citizens",
            "D. Has a minimum paid-up capital of ₱10 million"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_042",
        "question": "Under A.M. No. 24-10-14-SC, liveness verification during Remote Electronic Notarization (REN) is required to:",
        "choices": [
            "A. Test the internet connection speed of the principal",
            "B. Confirm that the person appearing is physically present and alive, preventing impersonation and spoofing attacks",
            "C. Record a video message for the notarial archive",
            "D. Satisfy BSP loan underwriting requirements"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_043",
        "question": "Under the Anti-Money Laundering Act (RA 9160, as amended by RA 10365), notaries public are classified as:",
        "choices": [
            "A. Exempt from all AML obligations because they are officers of the court",
            "B. Covered persons required to perform customer due diligence and report suspicious transactions to the AMLC",
            "C. Supervisory authorities responsible for auditing other covered persons",
            "D. Required to report only transactions exceeding ₱10 million in value"
        ],
        "answer": "B",
        "category": "Compliance"
    },
    {
        "id": "atty_044",
        "question": "Under A.M. No. 24-10-14-SC, cross-border notarization by a Philippine ENP is permitted when:",
        "choices": [
            "A. Both parties are located outside the Philippines",
            "B. The principal is a Filipino citizen or foreign national executing a document for use in the Philippines, subject to applicable Philippine rules",
            "C. The foreign country has a mutual recognition agreement with the Philippines only",
            "D. Cross-border notarization is strictly prohibited under current rules"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_045",
        "question": "Which of the following is a PROHIBITED ACT under the Notarial Practice Rules?",
        "choices": [
            "A. Charging a higher notarial fee than the minimum set by the IBP",
            "B. Notarizing an instrument where the signatory is not personally present (in-person) or properly connected via AVT (remote), or whose identity has not been verified",
            "C. Using an electronic seal in addition to the notarial certificate",
            "D. Maintaining a digital backup of the notarial register"
        ],
        "answer": "B",
        "category": "Notarial Practice"
    },
    {
        "id": "atty_046",
        "question": "An electronic notarial certificate under A.M. No. 24-10-14-SC must contain:",
        "choices": [
            "A. Only the ENP's name and digital signature",
            "B. The ENP's name, commission number, commission expiry date, jurisdiction, type of notarial act, and a statement that the required verification was performed",
            "C. A QR code linking to the Supreme Court website and a physical seal impression",
            "D. The client's full legal address and tax identification number"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_047",
        "question": "Under RA 8792, which type of transaction is EXCLUDED from being conducted entirely through electronic means?",
        "choices": [
            "A. Sale of goods and services",
            "B. Execution of negotiable instruments such as checks, promissory notes, and bills of exchange requiring physical delivery",
            "C. Filing of government forms and applications",
            "D. Banking transactions and fund transfers"
        ],
        "answer": "B",
        "category": "Legal Framework"
    },
    {
        "id": "atty_048",
        "question": "The penalty for performing notarial acts WITHOUT a valid notarial commission in the Philippines is:",
        "choices": [
            "A. A civil fine of ₱500 per act",
            "B. Criminal liability for falsification of public documents, in addition to administrative sanctions including disbarment proceedings",
            "C. A 30-day suspension from the IBP",
            "D. Mandatory retraining before a new commission can be applied for"
        ],
        "answer": "B",
        "category": "Notarial Practice"
    },
    {
        "id": "atty_049",
        "question": "Under A.M. No. 24-10-14-SC, conflict of interest rules prohibit an ENP from notarizing a document when:",
        "choices": [
            "A. The document involves real property valued over ₱5 million",
            "B. The ENP is a party to the instrument, a relative within the fourth civil degree of the principal, or has a direct financial interest in the transaction",
            "C. The document was prepared by the ENP's law firm",
            "D. The ENP has previously notarized documents for the same client"
        ],
        "answer": "B",
        "category": "ENP Rules"
    },
    {
        "id": "atty_050",
        "question": "Under RA 10173 and A.M. No. 24-10-14-SC, personal data collected during an e-notarization session may be retained by the ENP or platform for:",
        "choices": [
            "A. An indefinite period at the ENP's discretion",
            "B. Only as long as necessary for the purpose of the notarization, and in compliance with the minimum retention period required by law (ten years for the e-register), after which it must be securely disposed of",
            "C. A maximum of two years, after which all data must be deleted automatically",
            "D. No retention is allowed — all data must be deleted immediately after the session"
        ],
        "answer": "B",
        "category": "Data Privacy"
    },
]

# ─── CLIENT QUESTIONS (General Legal Awareness) ─────────────────────────────

CLIENT_QUESTIONS = [
    {
        "id": "cli_001",
        "question": "What does e-notarization mean?",
        "choices": [
            "A. Scanning a physical notarial seal onto a document",
            "B. The act of notarizing a document electronically using a certified Electronic Notary Public (ENP)",
            "C. Sending documents via email to a notary",
            "D. Having a document witnessed by two people online"
        ],
        "answer": "B",
        "category": "Basic Understanding"
    },
    {
        "id": "cli_002",
        "question": "Which government body accredits e-notarization platforms in the Philippines?",
        "choices": [
            "A. Department of Information and Communications Technology (DICT)",
            "B. Supreme Court of the Philippines",
            "C. Securities and Exchange Commission (SEC)",
            "D. National Privacy Commission (NPC)"
        ],
        "answer": "B",
        "category": "Basic Understanding"
    },
    {
        "id": "cli_003",
        "question": "An e-notarized document in the Philippines has the same legal effect as a:",
        "choices": [
            "A. Photocopy of the original",
            "B. Traditionally notarized paper document",
            "C. Certified true copy from the Register of Deeds",
            "D. Simple affidavit"
        ],
        "answer": "B",
        "category": "Legal Validity"
    },
    {
        "id": "cli_004",
        "question": "Your personal data shared on Quanby Legal is protected under which Philippine law?",
        "choices": [
            "A. Republic Act 9160 — Anti-Money Laundering Act",
            "B. Republic Act 10173 — Data Privacy Act of 2012",
            "C. Republic Act 8792 — E-Commerce Act",
            "D. Republic Act 11232 — Revised Corporation Code"
        ],
        "answer": "B",
        "category": "Data Privacy"
    },
    {
        "id": "cli_005",
        "question": "When you upload a document to Quanby Legal for notarization, you are communicating with a:",
        "choices": [
            "A. Government employee",
            "B. Supreme Court-accredited Electronic Notary Public (ENP)",
            "C. AI system that approves all documents automatically",
            "D. Bank representative"
        ],
        "answer": "B",
        "category": "Platform Knowledge"
    },
    {
        "id": "cli_006",
        "question": "What is the purpose of the liveness verification step during onboarding?",
        "choices": [
            "A. To take a profile photo for your account",
            "B. To verify you are a real, live person and match the identity document you provided",
            "C. To record a video for marketing purposes",
            "D. To check your internet connection speed"
        ],
        "answer": "B",
        "category": "Process Knowledge"
    },
    {
        "id": "cli_007",
        "question": "A contract is legally binding in the Philippines when it has:",
        "choices": [
            "A. A notarial seal and three witnesses",
            "B. Consent, object, and cause — even without notarization in most cases",
            "C. Government approval and BIR stamp",
            "D. A SEC registration number"
        ],
        "answer": "B",
        "category": "Civil Law Basics"
    },
    {
        "id": "cli_008",
        "question": "If you need to authorize someone to act on your behalf for a specific legal transaction, you need a:",
        "choices": [
            "A. Memorandum of Agreement",
            "B. Special Power of Attorney (SPA)",
            "C. Contract of Lease",
            "D. Certificate of Employment"
        ],
        "answer": "B",
        "category": "Document Types"
    },
    {
        "id": "cli_009",
        "question": "What does blockchain audit trail in Quanby Legal protect?",
        "choices": [
            "A. Your payment information",
            "B. The integrity and authenticity of your notarized document — it cannot be tampered with",
            "C. Your login password",
            "D. The notary's personal information"
        ],
        "answer": "B",
        "category": "Platform Knowledge"
    },
    {
        "id": "cli_010",
        "question": "Which of the following documents REQUIRES notarization to be legally effective in the Philippines?",
        "choices": [
            "A. A text message agreement between friends",
            "B. A Deed of Absolute Sale for real property",
            "C. An employment offer letter",
            "D. A company email policy"
        ],
        "answer": "B",
        "category": "Document Types"
    },
    {
        "id": "cli_011",
        "question": "During a Remote Electronic Notarization (REN) session, you will be required to:",
        "choices": [
            "A. Travel to the notary's office",
            "B. Appear via video call and present a valid government-issued ID",
            "C. Send your documents by courier",
            "D. Have a witness present in your location"
        ],
        "answer": "B",
        "category": "Process Knowledge"
    },
    {
        "id": "cli_012",
        "question": "Quanby Legal is compliant with BSP Circular 944, which means documents notarized here are accepted by:",
        "choices": [
            "A. Only Supreme Court-related proceedings",
            "B. BSP-supervised financial institutions such as banks and e-money issuers",
            "C. Foreign governments only",
            "D. LGUs for business permit applications only"
        ],
        "answer": "B",
        "category": "Regulatory"
    },
    {
        "id": "cli_013",
        "question": "Under Philippine law, you have the right to request a copy of your personal data held by Quanby Legal. This is called the:",
        "choices": [
            "A. Right to Privacy",
            "B. Right to Access",
            "C. Right to be Forgotten",
            "D. Right to Transparency"
        ],
        "answer": "B",
        "category": "Data Privacy"
    },
    {
        "id": "cli_014",
        "question": "An acknowledgment in a notarized document means that YOU have confirmed the document is:",
        "choices": [
            "A. Approved by the Supreme Court",
            "B. Your own free and voluntary act and deed, signed before the notary",
            "C. Tax-exempt",
            "D. Valid for international use"
        ],
        "answer": "B",
        "category": "Notarial Terms"
    },
    {
        "id": "cli_015",
        "question": "When using Quanby Legal, your data is encrypted using:",
        "choices": [
            "A. Simple password protection",
            "B. AES-256 encryption at rest and TLS 1.3 in transit",
            "C. A government-issued cipher code",
            "D. Standard ZIP compression"
        ],
        "answer": "B",
        "category": "Security"
    },
    {
        "id": "cli_016",
        "question": "If a contract is notarized, its evidentiary value in court compared to an unnotarized contract is:",
        "choices": [
            "A. The same — notarization has no effect on evidence",
            "B. Higher — a notarized document is a public instrument and presumed authentic",
            "C. Lower — courts prefer original unnotarized agreements",
            "D. Only higher if it has a Supreme Court stamp"
        ],
        "answer": "B",
        "category": "Legal Validity"
    },
    {
        "id": "cli_017",
        "question": "What type of ID is considered a competent evidence of identity for notarization in the Philippines?",
        "choices": [
            "A. Any school ID",
            "B. A current government-issued ID with photo and signature (e.g., passport, PhilSys, driver's license)",
            "C. An employment ID",
            "D. A barangay clearance"
        ],
        "answer": "B",
        "category": "Process Knowledge"
    },
    {
        "id": "cli_018",
        "question": "Quanby Legal's e-notarization service is available to clients located:",
        "choices": [
            "A. Only in Metro Manila",
            "B. Anywhere in the Philippines and eligible Filipinos abroad",
            "C. Only in Luzon",
            "D. Only in areas with fiber internet"
        ],
        "answer": "B",
        "category": "Platform Knowledge"
    },
    {
        "id": "cli_019",
        "question": "After successful e-notarization on Quanby Legal, your document is:",
        "choices": [
            "A. Sent to the Supreme Court for manual review",
            "B. Cryptographically sealed, recorded on blockchain, and available for download as a certified PDF",
            "C. Printed and mailed to your address",
            "D. Stored only on the notary's personal computer"
        ],
        "answer": "B",
        "category": "Platform Knowledge"
    },
    {
        "id": "cli_020",
        "question": "A Loan Agreement that is notarized:",
        "choices": [
            "A. Is automatically approved by the BSP",
            "B. Becomes a public instrument with stronger evidentiary weight and easier to enforce",
            "C. Waives all interest payments",
            "D. Requires SEC registration to be valid"
        ],
        "answer": "B",
        "category": "Document Types"
    },
]


def get_randomized_test(role: str = "attorney", count: int = 50) -> tuple[list, dict]:
    """
    Returns (client_questions, answer_key) for the given role.

    client_questions: list of question dicts WITHOUT 'answer' field — safe to send to browser.
    answer_key: {question_id: correct_answer_text} — stays server-side ONLY.

    Fix 11: Separates answer key from client-facing data at the model level.
    Fix 12: Stores full answer text (not letter) so shuffling can never corrupt the key.
    """
    pool = ATTORNEY_QUESTIONS if role == "attorney" else CLIENT_QUESTIONS

    # Return ALL questions shuffled (50 for attorneys)
    selected = pool.copy()
    random.shuffle(selected)

    client_questions = []
    answer_key: dict[str, str] = {}

    for i, q in enumerate(selected):
        choices = q["choices"].copy()
        # Get the full text of the correct answer before shuffling
        correct_answer_text = choices[ord(q["answer"]) - ord("A")]
        random.shuffle(choices)

        qid = q["id"]

        # Fix 12: Store the full answer TEXT in the key — immune to shuffle order
        answer_key[qid] = correct_answer_text

        # Fix 11: client_questions has NO 'answer' field
        client_questions.append({
            "number": i + 1,
            "id": qid,
            "question": q["question"],
            "choices": choices,
            "category": q["category"],
        })

    return client_questions, answer_key


def grade_test(
    questions_without_answers: list,
    answer_key: dict,
    user_answers: dict,
) -> dict:
    """
    Grade the test.

    Fix 11: Accepts separate answer_key dict (no 'answer' field on questions).
    Fix 12: Compares by answer text, not letter — robust against shuffle order.

    questions_without_answers: client question list (no 'answer' field)
    answer_key: {question_id: correct_answer_text}
    user_answers: {question_id: answer_letter_submitted_by_user}
    """
    total = len(questions_without_answers)
    correct = 0
    results = []

    for q in questions_without_answers:
        qid = q["id"]
        user_letter = user_answers.get(qid, "").upper()
        choices = q["choices"]

        # Resolve user's letter to the text they chose
        letter_idx = ord(user_letter) - ord("A") if user_letter else -1
        if 0 <= letter_idx < len(choices):
            user_answer_text = choices[letter_idx]
        else:
            user_answer_text = ""

        correct_answer_text = answer_key.get(qid, "")
        is_correct = bool(user_answer_text and user_answer_text == correct_answer_text)

        if is_correct:
            correct += 1

        results.append({
            "id": qid,
            "question": q["question"],
            "user_answer": user_letter,
            "user_answer_text": user_answer_text,
            "correct_answer_text": correct_answer_text,
            "is_correct": is_correct,
            "category": q["category"],
        })

    score_pct = round((correct / total) * 100, 1) if total > 0 else 0
    passed = score_pct >= 70  # 70% passing rate (35/50)

    return {
        "total": total,
        "correct": correct,
        "score_pct": score_pct,
        "passed": passed,
        "passing_score": 70,
        "results": results,
        "retake_fee_php": 500 if not passed else 0,
    }
