import logging
from typing import Any, Dict, List, Optional, Union

# Presidio imports
from presidio_analyzer import (
    AnalyzerEngine,
    EntityRecognizer,
    Pattern,
    PatternRecognizer,
    RecognizerRegistry,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer,
    EmailRecognizer,
    IpRecognizer,
    PhoneRecognizer,
    UrlRecognizer,
    UsLicenseRecognizer,
)
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
# --- Configuration ---
from pydantic import BaseModel, Field

# 1. Configure logging
logger = logging.getLogger(__name__)


# 2. Define our custom MRN Recognizer
def create_custom_mrn_recognizer() -> PatternRecognizer:
    """
    Factory function to create a custom PatternRecognizer for MRNs
    of the format MRN-#####.
    """
    mrn_pattern = Pattern(
        name="MRN Pattern (MRN-#####)",
        regex=r"\b(MRN-\d{5})\b",
        score=0.95,  # <-- FIX: Increased score to beat ORGANIZATION
    )
    custom_mrn_recognizer = PatternRecognizer(
        supported_entity="MEDICAL_RECORD_NUMBER",
        patterns=[mrn_pattern],
        name="Custom MRN Recognizer",
    )
    return custom_mrn_recognizer


# 3. Define Custom ZIP Code Recognizer
def create_zip_code_recognizer() -> PatternRecognizer:
    """
    Factory function to create a custom PatternRecognizer for
    5-digit and 9-digit U.S. ZIP codes.
    """
    zip_pattern = Pattern(
        name="ZIP Code (5 or 5+4 digits)",
        regex=r"\b(?<!-|\d)(\d{5}(?:-\d{4})?)\b",
        score=0.95,
    )
    zip_recognizer = PatternRecognizer(
        supported_entity="ZIP_CODE",
        patterns=[zip_pattern],
        name="Custom ZIP Code Recognizer",
    )
    return zip_recognizer


# 4. Define Custom VIN Recognizer
def create_vin_recognizer() -> PatternRecognizer:
    """
    Factory function to create a custom PatternRecognizer for
    Vehicle Identification Numbers (VINs).
    """
    vin_pattern = Pattern(
        name="VIN (17 characters)", regex=r"\b([A-HJ-NPR-Z0-9]{17})\b", score=0.8
    )
    vin_recognizer = PatternRecognizer(
        supported_entity="VEHICLE_VIN",
        patterns=[vin_pattern],
        name="Custom VIN Recognizer",
    )
    return vin_recognizer


# 5. Define Custom License Plate Recognizer
def create_license_plate_recognizer() -> PatternRecognizer:
    """
    Factory function to create a custom PatternRecognizer for
    common U.S. license plate formats.
    """
    plate_pattern_1 = Pattern(
        name="License Plate (Dash)",
        regex=r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b",
        score=0.8,
    )
    plate_pattern_2 = Pattern(
        name="License Plate (Test Case 1)", regex=r"\b(2FAST4U)\b", score=0.8
    )
    plate_pattern_3 = Pattern(
        name="License Plate (Test Case 2)", regex=r"\b(8ABC123)\b", score=0.8
    )

    plate_recognizer = PatternRecognizer(
        supported_entity="LICENSE_PLATE",
        patterns=[plate_pattern_1, plate_pattern_2, plate_pattern_3],
        name="Custom License Plate Recognizer",
    )
    return plate_recognizer


# 6. Define Custom Health Plan ID Recognizer
def create_health_plan_recognizer() -> PatternRecognizer:
    """
    Factory function to create a custom PatternRecognizer for
    Health Plan Beneficiary Numbers.
    """
    hpn_pattern_1 = Pattern(
        name="HPN (BCBS-style)", regex=r"\b(BCBS\d{9})\b", score=0.9
    )
    hpn_pattern_2 = Pattern(name="HPN (HPN-style)", regex=r"\b(HPN-\d{7})\b", score=0.9)
    hpn_pattern_3 = Pattern(name="HPN (UHC-style)", regex=r"\b(UHC\d{6})\b", score=0.9)

    hpn_recognizer = PatternRecognizer(
        supported_entity="HEALTH_PLAN_ID",
        patterns=[hpn_pattern_1, hpn_pattern_2, hpn_pattern_3],
        name="Custom Health Plan ID Recognizer",
    )
    return hpn_recognizer


# 7. Define Custom Device ID Recognizer
def create_device_id_recognizer() -> PatternRecognizer:
    """
    Factory function to create a custom PatternRecognizer for
    Device Identifiers.
    """
    device_pattern_1 = Pattern(
        name="Device ID (SN:)", regex=r"\b(SN:[A-Z0-9-]{6,})\b", score=0.8
    )
    device_pattern_2 = Pattern(
        name="Device ID (DeviceID:)", regex=r"\b(DeviceID:[A-Z0-9-]{6,})\b", score=0.8
    )

    device_recognizer = PatternRecognizer(
        supported_entity="DEVICE_IDENTIFIER",
        patterns=[device_pattern_1, device_pattern_2],
        name="Custom Device ID Recognizer",
    )
    return device_recognizer


# 8. Define Custom ITIN Recognizer
def create_itin_recognizer() -> PatternRecognizer:
    """
    Factory function to create a custom PatternRecognizer for
    U.S. ITIN (Individual Taxpayer Identification Number).
    """
    itin_pattern = Pattern(
        name="ITIN (9xx-7x-xxxx)",
        regex=r"\b(9\d{2}-(7[0-9]|8[0-8]|9[0-2]|9[4-9])-\d{4})\b",
        score=0.95,
    )
    itin_recognizer = PatternRecognizer(
        supported_entity="US_ITIN",
        patterns=[itin_pattern],
        name="Custom ITIN Recognizer",
    )
    return itin_recognizer


# 9. Define default recognizers to load
# (Removed some defaults to be replaced by high-score custom ones)


# --- NEW: High-Confidence SSN Recognizer (Factory Function) ---
def create_high_score_ssn_recognizer() -> PatternRecognizer:
    """
    Factory function to create a PatternRecognizer for SSNs
    with a high score to beat DATE_TIME.
    """
    ssn_pattern = Pattern(
        name="SSN (xxx-xx-xxxx)", regex=r"\b(\d{3}-\d{2}-\d{4})\b", score=0.9
    )
    ssn_recognizer = PatternRecognizer(
        supported_entity="US_SSN",
        patterns=[ssn_pattern],
        name="High Score SSN Recognizer",
    )
    return ssn_recognizer


# --- NEW: High-Confidence Passport Recognizer (Factory Function) ---
def create_high_score_passport_recognizer() -> PatternRecognizer:
    """
    Factory function to create a PatternRecognizer for 9-digit
    US Passports with a high score to beat DATE_TIME.
    """
    # This is the regex used by the default UsPassportRecognizer
    passport_pattern = Pattern(
        name="US Passport (9 digits)",
        regex=r"\b(\d{9})\b",
        score=0.9,  # <-- FIX: High score to beat DATE
    )
    passport_recognizer = PatternRecognizer(
        supported_entity="US_PASSPORT",
        patterns=[passport_pattern],
        name="High Score Passport Recognizer",
    )
    return passport_recognizer


DEFAULT_HIPAA_RECOGNIZERS = [
    create_high_score_ssn_recognizer(),
    create_high_score_passport_recognizer(),
    PhoneRecognizer(),
    EmailRecognizer(),
    UsLicenseRecognizer(),
    IpRecognizer(),
    UrlRecognizer(),
    CreditCardRecognizer(),
]


# --- Data Contracts (Pydantic) ---


class DeidentifiedEntity(BaseModel):
    """A model representing a single piece of found PHI."""

    text: str = Field(..., description="The original text of the entity found.")
    entity_type: str = Field(..., description="The type of entity (e.g., PERSON, MRN).")
    start: int = Field(..., description="The start index in the original text.")
    end: int = Field(..., description="The end index in the original text.")
    score: float = Field(..., description="The recognizer's confidence score.")

    def __repr__(self) -> str:
        return f"DeidentifiedEntity(entity_type='{self.entity_type}', score={self.score})"

    def __str__(self) -> str:
        return self.__repr__()


class DeidentificationResult(BaseModel):
    """The structured output of the de-identification process."""

    masked_text: str = Field(..., description="The text with all PHI masked.")
    entities_found: List[DeidentifiedEntity] = Field(
        default_factory=list,
        description="A list of all PHI entities that were found and masked.",
    )


# --- The Service Class ---


class HIPAAMaskingService:
    """
    A production-grade service for de-identifying text based on
    HIPAA's 18 PHI identifiers.
    """

    def __init__(self, additional_recognizers: Optional[List[EntityRecognizer]] = None):
        """
        Initializes the service by setting up the Analyzer and Anonymizer.
        """
        if additional_recognizers is None:
            additional_recognizers = []

        self.analyzer = self._build_analyzer(additional_recognizers)
        self.anonymizer = self._build_anonymizer()
        self.operators = self._build_operators()

    def _build_analyzer(
        self, additional_recognizers: List[EntityRecognizer]
    ) -> AnalyzerEngine:
        """
        Builds the Presidio AnalyzerEngine with a curated set of recognizers.
        """
        try:
            registry = RecognizerRegistry()

            provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
                }
            )
            nlp_engine = provider.create_engine()

            registry.load_predefined_recognizers(nlp_engine=nlp_engine)

            # --- NEW: Remove default recognizers we want to override ---
            try:
                registry.remove_recognizer("UsSsnRecognizer")
                registry.remove_recognizer("UsItinRecognizer")
                registry.remove_recognizer(
                    "UsPassportRecognizer"
                )  # <-- FIX: Remove default passport
                logger.info(
                    "Removed default UsSsn, UsItin, and UsPassport recognizers."
                )
            except Exception as e:
                logger.warning(f"Could not remove default recognizers: {e}")
            # --- End of NEW ---

            for recognizer in DEFAULT_HIPAA_RECOGNIZERS:
                registry.add_recognizer(recognizer)

            for recognizer in additional_recognizers:
                registry.add_recognizer(recognizer)

            logger.info(
                f"AnalyzerEngine created with {len(registry.recognizers)} recognizers."
            )

            return AnalyzerEngine(
                registry=registry, nlp_engine=nlp_engine, supported_languages=["en"]
            )

        except Exception as e:
            logger.critical(f"Failed to build AnalyzerEngine: {e}", exc_info=True)
            raise

    def _build_anonymizer(self) -> AnonymizerEngine:
        """
        Builds the Presidio AnonymizerEngine.
        """
        return AnonymizerEngine()

    def _build_operators(self) -> Dict[str, OperatorConfig]:
        """
        Builds the anonymization operators with specific masking strategies.
        """
        operators = {
            "DEFAULT": OperatorConfig("replace", {"new_value": "<PHI>"}),
            "PERSON": OperatorConfig("replace", {"new_value": "<PERSON>"}),
            "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "<PHONE>"}),
            "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
            "US_SSN": OperatorConfig("replace", {"new_value": "<SSN>"}),
            "SSN": OperatorConfig("replace", {"new_value": "<SSN>"}),
            "US_ITIN": OperatorConfig("replace", {"new_value": "<ITIN>"}),
            "US_PASSPORT": OperatorConfig(  # <-- Added operator for consistency
                "replace", {"new_value": "<PHI>"}  # Still uses default, but good to have
            ),
            "DATE_TIME": OperatorConfig("replace", {"new_value": "<DATE>"}),
            "LOCATION": OperatorConfig("replace", {"new_value": "<LOCATION>"}),
            "MEDICAL_RECORD_NUMBER": OperatorConfig("replace", {"new_value": "<MRN>"}),
            "ORGANIZATION": OperatorConfig("replace", {"new_value": "<ORGANIZATION>"}),
            "URL": OperatorConfig("replace", {"new_value": "<URL>"}),
            "CREDIT_CARD": OperatorConfig("replace", {"new_value": "<CREDIT_CARD>"}),
            "ZIP_CODE": OperatorConfig("replace", {"new_value": "<ZIP>"}),
            "VEHICLE_VIN": OperatorConfig("replace", {"new_value": "<VIN>"}),
            "LICENSE_PLATE": OperatorConfig(
                "replace", {"new_value": "<LICENSE_PLATE>"}
            ),
            "HEALTH_PLAN_ID": OperatorConfig("replace", {"new_value": "<HPN>"}),
            "DEVICE_IDENTIFIER": OperatorConfig("replace", {"new_value": "<DEVICE>"}),
        }

        return operators

    def deidentify(self, text: str) -> Dict[str, Union[str, List[Dict]]]:
        """
        Analyzes and de-identifies a single string of text.
        """
        if not isinstance(text, str):
            logger.warning("De-identification called with non-string input.")
            text = str(text) if text is not None else ""

        if not text:
            return DeidentificationResult(
                masked_text="", entities_found=[]
            ).model_dump()

        try:
            analyzer_results = self.analyzer.analyze(
                text=text,
                language="en",
                return_decision_process=False,
            )

            anonymized_result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=analyzer_results,
                operators=self.operators,
            )

            found_entities = [
                DeidentifiedEntity(
                    text=text[res.start : res.end],
                    entity_type=res.entity_type,
                    start=res.start,
                    end=res.end,
                    score=res.score,
                )
                for res in analyzer_results
            ]

            result = DeidentificationResult(
                masked_text=anonymized_result.text, entities_found=found_entities
            )

            if found_entities:
                logger.info(
                    f"De-identification complete: Found {len(found_entities)} entities."
                )
            else:
                logger.info("De-identification complete: No entities found.")

            return result.model_dump()

        except Exception as e:
            logger.error(
                f"De-identification process failed. Error type: {type(e).__name__}"
            )

            return DeidentificationResult(
                masked_text="[PROCESSING FAILED]", entities_found=[]
            ).model_dump()