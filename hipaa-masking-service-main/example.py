import json

from hipaa_masking_service import (
    HIPAAMaskingService,
    create_custom_mrn_recognizer,
    create_device_id_recognizer,
    create_health_plan_recognizer,
    create_itin_recognizer,
    create_license_plate_recognizer,
    create_vin_recognizer,
    create_zip_code_recognizer,
)


def get_service() -> HIPAAMaskingService:
    """
    Helper function to build and return a fully configured
    HIPAAMaskingService instance.
    """
    # Create all the custom recognizers
    custom_mrn_rec = create_custom_mrn_recognizer()
    zip_code_rec = create_zip_code_recognizer()
    vin_rec = create_vin_recognizer()
    plate_rec = create_license_plate_recognizer()
    hpn_rec = create_health_plan_recognizer()
    device_rec = create_device_id_recognizer()
    itin_rec = create_itin_recognizer()

    # Initialize the service with ALL custom recognizers
    service_instance = HIPAAMaskingService(
        additional_recognizers=[
            custom_mrn_rec,
            zip_code_rec,
            vin_rec,
            plate_rec,
            hpn_rec,
            device_rec,
            itin_rec,
        ]
    )
    print("✅ HIPAAMaskingService initialized with all custom recognizers.")
    return service_instance


def main():
    """
    Main function to run the de-identification on example data.
    """

    service = get_service()

    # --- Unseen Data ---
    # A list of new sentences to test the service
    unseen_data = [
        # 1. Mix of NLP (PERSON, DATE_TIME) and Regex (ZIP, PHONE)
        "On 04/12/2025, Mr. John Smith (phone: 555-888-9999) visited our clinic at 123 Wellness Rd, Anytown, 90211.",
        # 2. Mix of custom recognizers (MRN, HPN, DEVICE)
        "Patient's file (MRN-90909) and health plan (BCBS112233445) were updated. The device used was DeviceID:XYZ-7890.",
        # 3. No PHI
        "This is a general note about hospital procedures.",
        # 4. Sensitive numbers (SSN, ITIN, PASSPORT)
        "A copy of the driver's passport (123456789) and SSN (987-65-4321) are required. ITIN 922-80-1234 was also noted.",
        # 5. Vehicle and Location
        "The accident involved a Honda Civic (VIN: 1HGCV1F93LA123456) with license plate 8ABC123 near Chicago.",
        # 6. Email and IP
        "Please send results to patient-contact@private-domain.com. The request was logged from IP 192.168.1.100.",
        # 7. Credit card
        "Payment on file: Visa 4111222233334444.",
        # 8. --- NEW: Dense Paragraph Example ---
        (
            "Patient Jane A. Doe (DOB: 1985-02-10) visited the clinic today. "
            "Her new address is 456 Oak Avenue, Springfield, IL 62704, and she updated "
            "her contact information to jane.doe85@example.net and phone (217) 555-1234. "
            "Her patient ID is P-987654, and her insurance policy number is XZ-12345-6789. "
            "During the check-in, she confirmed her Social Security Number as 987-65-4321 "
            "and her driver's license, Y123-456-789, was scanned. "
            "The visit was logged from IP address 172.217.14.228."
        ),
    ]

    print("\n--- Processing Unseen Data ---")

    for i, text in enumerate(unseen_data):
        result = service.deidentify(text)

        print(f"\n--- Example {i+1} ---")
        print(f"Original:   {text}")
        print(f"Masked:     {result['masked_text']}")

        # list of entities found
        if result["entities_found"]:
            print("Entities:")
            # Pretty print the list of entity dictionaries
            print(json.dumps(result["entities_found"], indent=2))


if __name__ == "__main__":
    main()