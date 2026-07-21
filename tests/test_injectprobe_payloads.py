from injectprobe.payloads import load_payloads


def test_default_payloads_load_and_are_well_formed():
    payloads = load_payloads()
    assert len(payloads) >= 20

    ids = [p.id for p in payloads]
    assert len(ids) == len(set(ids))

    for p in payloads:
        assert p.category
        assert p.prompt.strip()
        assert all(isinstance(tag, str) for tag in p.owasp)


def test_excessive_agency_category_maps_to_llm06():
    payloads = load_payloads()
    agency_payloads = [p for p in payloads if p.category == "excessive_agency"]
    assert agency_payloads
    assert all("LLM06" in p.owasp for p in agency_payloads)
