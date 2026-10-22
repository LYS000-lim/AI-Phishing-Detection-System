from collections import Counter
from datetime import date, datetime, time, timedelta, timezone
from typing import List, Optional
from urllib.parse import urlparse

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import Integer, desc, func
from sqlalchemy.orm import Session

from .auth import current_user, hash_password, verify_password
from .allowlist import is_trusted, unwrap_redirect
from .database import get_db
from .explanations import (
    _english_join, _feature_clause, _technique_summary_bullets, build_evidence,
    build_reason_bullets, MODEL_LINE_MARKERS, model_signal_line, plain_text_explanation, risk_level,
)
from .features import FEATURE_ORDER, extract_features
from .ml_state import (
    UNCERTAIN_THRESHOLD, get_lime_explainer, get_shap_explainer, homepage_score, model_info, MODEL,
    what_if_changes,
)
from .models import Detection, ReportedURL, User, UserBlockedURL
from .schemas import (
    BatchRequest, DetectionOut, PasswordChange, ProfileUpdate,
    ReportURLRequest, ReportedURLOut,
    URLRequest, UserOut,
)

from .phishing_type import detect_phishing_type
from .pipeline import evaluate
from .stage2 import describe_age
from .score_view import TRUSTED_SCORE, VERDICT_KEY, verdict_counts

router = APIRouter(tags=["user"])

# Why a URL was Suspicious before the live page check (explain()).
_URL_REASON = {
    "reputable_domain": "its address pattern resembles phishing",
    "borderline": "its phishing score was in the borderline range",
    "https_only": "it does not use a secure HTTPS connection",
}


def _age_note(s2: dict, prediction: str = "legitimate") -> str:
    """What the domain's age means for this verdict. An old domain on a
    Phishing result must not read as a reason the site is safe."""
    if s2["age_days"] < 365:
        return ("New domains are common for phishing, because most phishing domains are bought "
                "days or weeks before an attack and abandoned soon after.")
    if prediction == "phishing":
        return ("An older domain does not make a website safe. Attackers also use hacked or "
                "long-held domains, and here the address itself shows strong phishing signs, "
                "so the age was not enough to clear it.")
    if prediction == "uncertain":
        return ("Phishing domains are usually only days or weeks old and this one is older, "
                "which lowers the risk but does not clear the warning signs in the address.")
    if s2["age_days"] < 5 * 365:
        return ("Phishing domains are usually only days or weeks old and this one is older, "
                "which supports the legitimate result.")
    return ("Phishing domains are rarely kept this long, because most are bought days or "
            "weeks before an attack, so the age supports the legitimate result.")


def _age_line(verdict: dict, url: str, prediction: str = "legitimate") -> str:
    """The domain-age point of the "Why" text: the registration date, or why
    there is none (shortener links are explained by their own rule)."""
    from .reputation import is_user_content_host
    s2, rep = verdict["stage2"], verdict.get("reputation") or {}
    if s2:
        line = (f"Domain age — {s2['domain']} was registered {describe_age(s2['age_days'])} "
                f"({s2['registered']}). {_age_note(s2, prediction)}")
        if s2.get("changed") == "raised":
            line += " This raised the result above what the address alone gave."
        elif s2.get("changed") == "lowered":
            line += " This lowered the result below what the address alone gave."
        return line
    if rep.get("shortener"):
        return ""
    if is_user_content_host(url):
        return (f"Domain age — not used: {urlparse(url).hostname} is on a shared platform where "
                f"anyone can create pages, so the age of {rep.get('domain') or 'the domain'} says "
                "nothing about this page.")
    return (f"Domain age — the registration date of {rep.get('domain') or urlparse(url).hostname} "
            "could not be found, so the domain's age was not used.")


def _page_lines(page, prediction: str) -> list:
    """The live page check's part of the "Why" text, for every verdict:
    what it found, or why it was not run or could not open the page."""
    if page is None:
        if prediction == "legitimate":
            return ["Live page check — not run, because the address already looked legitimate, "
                    "so the result is based on the address only."]
        return ["Live page check — not run, so the result is based on the address only."]
    risks = [s["text"] for s in page["signals"] if s["kind"] == "risk"]
    if risks:
        return [f"Live page check — {text}" for text in risks]
    if not page["reachable"]:
        info = next((s["text"] for s in page["signals"] if s["kind"] == "info"), "")
        return [f"Live page check — {info or 'the page could not be opened.'} "
                "The result is based on the address only."]
    if prediction == "phishing":
        return ["Live page check — the page opened but showed no extra sign such as a password "
                "form sending data to another server. This does not clear it, because phishing "
                "pages often hide their content from automated checks, so the verdict comes from "
                "the address signals above."]
    return ["Live page check — the page opened and showed no sign such as a password form "
            "sending data to another server, so it did not change the result."]


def _age_card(s2: dict, prediction: str = "legitimate") -> dict:
    """Evidence card for the domain-age check (red when it raised the
    result, green when it lowered it)."""
    raised = s2.get("changed") == "raised" or s2["age_days"] < 365
    return {
        "title": "Recently Registered Domain" if raised else "Long-Established Domain",
        "feature": "DomainAge",
        "detected_value": f"{s2['registered']} ({describe_age(s2['age_days'])})",
        "shap_contribution": 1 if raised else -1,
        "lime_contribution": 0,
        "found": f"The domain {s2['domain']} was registered {describe_age(s2['age_days'])}.",
        "why_it_matters": _age_note(s2, prediction),
        "support": ("Raised the result (domain-age check)" if raised
                    else "Lowered the result (domain-age check)"),
    }


# ---------------------------------------------------------------------------
# Scan / predict
# ---------------------------------------------------------------------------
def _predict_and_log(
    url: str,
    user: User,
    db: Session,
    ip: Optional[str] = None,
    source: str = "website",
) -> dict:
    if MODEL is None and not is_trusted(unwrap_redirect(url)):
        raise HTTPException(
            503,
            "Trained model is not available yet. Run "
            "`python notebooks/train_and_compare.py` against the "
            "PhiUSIIL CSV to generate outputs/deployment_model.joblib, "
            "then restart the API. (Trusted domains still work via the "
            "reputation allowlist.)",
        )

    # pipeline.evaluate: redirect unwrapping, allowlist, model + rules and
    # the live page check. A redirect or short link is checked by the
    # address it opens; the log keeps the URL the user entered.
    result = evaluate(url)
    checked, checked_url = result["checked"], result["checked_url"]

    # Reputation-list bypass: well-known trusted domains skip ML
    # classification entirely. This is a separate result state from an ML
    # legitimate prediction and therefore returns trusted_domain=True.
    if result["trusted"]:
        domain = result["trusted"]
        features = extract_features(checked)
        record = Detection(
            user_id=user.id,
            url=url,
            prediction="legitimate",
            label=0,
            confidence=1.0,
            phishing_probability=0.0,
            risk_level="Low",
            model_used="TrustedAllowlist",
            ip_address=ip,
            source=source,
            risk_score=0.0,
            score_confidence=1.0,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return {
            "id": record.id,
            "url": url,
            "checked_url": checked_url,
            "unicode_host": result["unicode_host"],
            "prediction": "legitimate",
            "label": 0,
            "confidence": 1.0,
            "score": TRUSTED_SCORE,
            "phishing_probability": 0.0,
            "legitimate_probability": 1.0,
            "risk_level": "Low",
            "model_used": "TrustedAllowlist",
            "trusted_domain": True,
            "matched_domain": domain,
            "security_status": "Trusted Website",
            "features": features,
            "attack_type": None,
            "created_at": record.created_at.isoformat(),
        }

    # Tuned thresholds + the missing-HTTPS softening live in one place
    # (explanations.classify). `label`/`phishing_probability` still store
    # the model's raw decision, so dashboard/aggregate stats keep reporting
    # true model behaviour -- only prediction/risk_level are softened.
    features, verdict = result["features"], result["verdict"]
    label = verdict["label"]                           # 0=Legit, 1=Phish
    p_phish = verdict["p_phish"]
    confidence = verdict["confidence"]
    prediction = verdict["prediction"]
    risk = verdict["risk"]

    attack_type = None
    if prediction == "phishing":
        attack_type = detect_phishing_type(checked, features)

    record = Detection(
        user_id=user.id,
        url=url,
        prediction=prediction,
        label=label,
        confidence=round(confidence, 4),
        phishing_probability=round(p_phish, 4),
        risk_level=risk,
        model_used=model_info()["name"],
        attack_type=attack_type["category"] if attack_type else None,
        ip_address=ip,
        source=source,
        risk_score=verdict["score"]["risk_score"],
        score_confidence=verdict["score"]["confidence"],
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "id": record.id,
        "url": url,
        "checked_url": checked_url,
        "unicode_host": result["unicode_host"],
        "prediction": prediction,
        "label": label,
        "confidence": round(confidence, 4),
        "phishing_probability": round(p_phish, 4),
        "legitimate_probability": round(1 - p_phish, 4),
        "risk_level": risk,
        "model_used": model_info()["name"],
        "trusted_domain": False,
        "uncertain_reason": verdict["uncertain_reason"],
        "legit_reason": verdict["legit_reason"],
        "escalated_by": verdict["escalated_by"],
        "brand": verdict["brand"],
        "lookalike": verdict["lookalike"],
        "lures": verdict["lures"],
        "page_check": verdict["page_check"],
        "stage2": verdict["stage2"],
        "reputation": verdict["reputation"],
        "score": verdict["score"],
        "features": features,
        "attack_type": attack_type,
        "created_at": record.created_at.isoformat(),
    }


@router.post("/api/scan")
def scan(
    req: URLRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    try:
        return _predict_and_log(
            req.url, user, db, ip=request.client.host if request.client else None,
        )
    except Exception as exc:
        raise HTTPException(422, f"Could not process URL: {exc}")


@router.post("/api/scan/batch")
def scan_batch(
    req: BatchRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    ip = request.client.host if request.client else None
    results, errors = [], []
    for u in req.urls:
        try:
            results.append(_predict_and_log(u, user, db, ip=ip))
        except Exception as exc:
            errors.append({"url": u, "error": str(exc)})
    return {"count": len(results), "results": results, "errors": errors}


# ---------------------------------------------------------------------------
# Individual explanation (SHAP + LIME + plain-text summary)
# ---------------------------------------------------------------------------
@router.post("/api/explain")
def explain(req: URLRequest, user: User = Depends(current_user)):
    if MODEL is None and not is_trusted(unwrap_redirect(req.url)):
        raise HTTPException(503, "Trained model is not available.")

    # Same check as the scan (cached page check, so both agree). A redirect
    # or short link is explained by the address it opens. For a Phishing
    # result the page check only adds findings.
    try:
        result = evaluate(req.url, page_for=("uncertain", "phishing"))
    except Exception as exc:
        raise HTTPException(422, f"Could not process URL: {exc}")
    url, checked_url = result["checked"], result["checked_url"]
    if result["unicode_host"]:
        redirect_note = [
            f"The address is written with special Unicode letters "
            f"({urlparse(req.url).hostname}). Browsers open it as {urlparse(url).hostname}, "
            "so the result is for that website."
        ]
    else:
        redirect_note = (
            [f"This link is a redirect: it opens {urlparse(url).hostname}, so the result is "
             "for that website."]
            if checked_url else []
        )

    # Trusted-domain results are decided by reputation verification, not by
    # the ML model. Return a dedicated explanation state with no SHAP/LIME.
    if result["trusted"]:
        domain = result["trusted"]
        return {
            "url": req.url,
            "checked_url": checked_url,
            "unicode_host": result["unicode_host"],
            "prediction": "legitimate",
            "risk_level": "Low",
            "confidence": 1.0,
            "score": TRUSTED_SCORE,
            "phishing_probability": 0.0,
            "legitimate_probability": 1.0,
            "model_used": "TrustedAllowlist",
            "trusted_domain": True,
            "matched_domain": domain,
            "security_status": "Trusted Website",
            "security_analysis": [
                "This website has been verified as an official trusted domain.",
                "The URL structure does not contain suspicious characteristics commonly observed in phishing websites.",
            ],
            "why_detected": redirect_note + [
                f"The official domain '{domain}' matched the trusted-domain allowlist.",
                "Trusted-domain verification completed successfully, so an ML explanation was not required.",
                "Domain age and live page check — not run, because the domain is on the trusted list.",
            ],
            "plain_text": (
                f"The official domain '{domain}' matched the trusted-domain "
                "allowlist. ML classification was not required."
            ),
            "attack_analysis": None,
            "evidence": [],
            "shap": {
                "note": "Trusted-domain verification - SHAP not computed.",
                "top_features": [],
            },
            "lime": {
                "note": "Trusted-domain verification - LIME not computed.",
                "top_rules": [],
            },
        }

    vec, features, verdict = result["vec"], result["features"], result["verdict"]
    label = verdict["label"]
    p_phish = verdict["p_phish"]
    # Numbers in the text: the URL model's own (raw) score, as in the SHAP
    # chart, and the result page's Score (score_view.py) for the result.
    final_score = verdict["score"]["risk_score"]
    prediction = verdict["prediction"]
    risk = verdict["risk"]
    uncertain_reputable = verdict["uncertain_reason"] == "reputable_domain"
    uncertain_https = verdict["uncertain_reason"] == "https_only"
    uncertain_borderline = verdict["uncertain_reason"] == "borderline"
    uncertain_brand = verdict["uncertain_reason"] == "brand_impersonation"
    lures = verdict["lures"]
    # What kept a warning on a well-established domain (ml_state.lure_signals).
    lure_sentence = lure_reason = ""
    if lures:
        lure_sentence = (
            f"The address also contains {_english_join(lures)}, which a phishing page "
            "on a shared or hacked website relies on, so the warning stays."
        )
        lure_reason = (
            f"{verdict['reputation']['domain']} is a well-established website, but the "
            f"address contains {_english_join(lures)}, which a phishing page on a "
            "shared or hacked website relies on."
        )

    # SHAP contributions for class 1 (phishing).
    shap_exp = get_shap_explainer()
    shap_vals = shap_exp.shap_values(vec)
    arr = np.asarray(shap_vals)
    if arr.ndim == 3:                       # (samples, features, classes)
        contrib = arr[0, :, 1]
    elif isinstance(shap_vals, list):       # [class0, class1]
        contrib = np.asarray(shap_vals[1])[0]
    else:                                   # single-class output
        contrib = arr[0]

    shap_out = sorted(
        (
            {"feature": f, "shap_value": round(float(v), 5)}
            for f, v in zip(FEATURE_ORDER, contrib)
        ),
        key=lambda d: abs(d["shap_value"]),
        reverse=True,
    )[:10]
    # Starting point of the SHAP chart: the model's average phishing score.
    base = np.ravel(shap_exp.expected_value)
    shap_base = float(base[1] if base.size > 1 else base[0])

    # What-if: the top features re-scored one at a time with a value
    # typical of the opposite class (ml_state.what_if_changes).
    what_if = what_if_changes(vec, contrib, prediction)

    # LIME local rules for the phishing class.
    lime_exp = get_lime_explainer()
    explanation = lime_exp.explain_instance(
        vec[0], MODEL.predict_proba, num_features=10, labels=[1],
    )
    lime_out = [
        {"rule": rule, "weight": round(float(w), 5)}
        for rule, w in explanation.as_list(label=1)
    ]

    attack_analysis = (
        detect_phishing_type(url, features)
        if prediction == "phishing"
        else None
    )

    page = verdict["page_check"]
    if verdict["legit_reason"] == "page_check":
        # Suspicious on the URL alone; the live page check found a normal
        # page of this well-established website (pipeline.apply_page_check).
        rep = verdict["reputation"]
        safe = [s["text"] for s in page["signals"] if s["kind"] == "safe"]
        url_part = _URL_REASON.get(verdict.get("url_reason"), "its address pattern resembles phishing")
        if lures:
            url_part += f" and it contains {_english_join(lures)}"
        why_detected = build_reason_bullets("legitimate", features, shap_out, limit=1) + [
            f"On the URL alone this address was Suspicious: {url_part}.",
            f"{rep['domain']} is a well-established website (Tranco rank #{rep['rank']:,}), so a "
            "page that names only this website and sends no password to an unknown server is "
            "treated as legitimate.",
        ] + [f"Live page check — {text}" for text in safe]
        evidence = build_evidence("legitimate", features, shap_out, lime_out, limit=3)
        plain = (
            f"Legitimate. On the URL alone this address looked suspicious ({url_part}), but "
            f"the live page check found a normal page of {rep['domain']} that names only this "
            "website and sends no password to an unknown server."
        )
        security_analysis = safe + [
            "The page was opened by the server without running its scripts. A phishing page "
            "can show automated visitors different content, so stay alert if a page asks for "
            "details it should not need.",
        ]
    elif verdict["escalated_by"] == "page_check":
        # The live page check found a phishing behaviour on the page.
        risks = [s["text"] for s in page["signals"] if s["kind"] == "risk"]
        if verdict.get("url_reason") == "brand_impersonation":
            url_part = (f"it uses the brand name \"{verdict['brand']}\" on a domain the brand "
                        f"does not own, with a URL pattern score of {p_phish:.0%}")
        else:
            url_part = (f"{_URL_REASON.get(verdict.get('url_reason'), 'borderline URL signals')}, "
                        f"with a URL pattern score of {p_phish:.0%}")
        why_detected = [
            f"On the URL alone this address was only Suspicious ({url_part}), and what the "
            "page itself does is what raised the verdict to phishing.",
        ] + [f"Live page check — {text}" for text in risks]
        evidence = build_evidence(prediction, features, shap_out, lime_out, limit=3)
        plain = (
            f"Phishing. The live page check found: {risks[0]} Do not enter passwords or "
            "payment details."
        )
        security_analysis = None
    elif "new_domain" in (verdict["uncertain_reason"], verdict["escalated_by"]):
        # Domain-age check (stage2.py): a recently registered domain raised
        # the verdict above what the URL pattern alone gave. The age itself
        # is added to the "Why" text below, after the model signals.
        s2 = verdict["stage2"]
        why_detected = build_reason_bullets("phishing", features, shap_out,
                                            attack_analysis=attack_analysis, limit=3)
        evidence = build_evidence("phishing", features, shap_out, lime_out, limit=2) + [_age_card(s2, prediction)]
        plain = (
            f"{'Phishing' if prediction == 'phishing' else 'Suspicious'}. This website's domain "
            f"was registered {describe_age(s2['age_days'])}. New domains are a strong sign of "
            f"phishing, and together with the URL pattern score ({p_phish:.0%}) the domain-age "
            f"check gives a score of {final_score:.0%}. Do not enter passwords or payment "
            "details unless you are sure who runs this website."
        )
        security_analysis = None if prediction == "phishing" else [
            f"The domain {s2['domain']} was registered {describe_age(s2['age_days'])} "
            f"({s2['registered']}), recently compared with most genuine websites.",
            "The URL pattern alone was not enough for a warning, and the domain's age is what "
            "raised this result.",
        ]
    elif "established_domain" in (verdict["uncertain_reason"], verdict["legit_reason"]):
        # Domain-age check: a long-held domain lowered the verdict below what
        # the URL pattern alone gave. The age itself is added to the "Why"
        # text below, after the model signals.
        s2 = verdict["stage2"]
        if prediction == "legitimate":
            why_detected = build_reason_bullets("legitimate", features, shap_out, limit=1)
            evidence = build_evidence("legitimate", features, shap_out, lime_out, limit=2)
        else:
            why_detected = build_reason_bullets("phishing", features, shap_out, limit=2)
            evidence = build_evidence("phishing", features, shap_out, lime_out, limit=2)
            for card in evidence:
                card["support"] = "Raised the URL pattern score (outweighed by the domain's age)"
        evidence.append(_age_card(s2, prediction))
        if lures:
            why_detected.append(f"The address contains {_english_join(lures)}, and a long-established "
                                "website can still be hacked, so check the address before signing in.")
        plain = (
            f"{'Legitimate' if prediction == 'legitimate' else 'Suspicious'}. The address pattern "
            f"resembles phishing ({p_phish:.0%}), but its domain {s2['domain']} has existed since "
            f"{s2['registered'][:4]}, and with the domain's age the score is {final_score:.0%}."
        )
        security_analysis = [
            f"The domain {s2['domain']} was registered in {s2['registered'][:4]}, long before "
            "typical phishing domains.",
            "A long-established website can still be hacked, so stay alert if the page asks for "
            "details it should not need.",
        ]
    elif uncertain_reputable:
        # The model scored the URL text as phishing, but the registered
        # domain is a well-established website, so the verdict is capped.
        rep = verdict["reputation"]
        why_detected = build_reason_bullets(
            "phishing", features, shap_out, attack_analysis=None, limit=3,
        )
        evidence = build_evidence("phishing", features, shap_out, lime_out, limit=3)
        plain = (
            "Suspicious. The address pattern resembles phishing, but it belongs "
            f"to {rep['domain']}, a well-established "
            f"website (ranked #{rep['rank']:,} globally), so it is not treated as "
            "confirmed phishing. Make sure the domain is exactly "
            f"{rep['domain']} before entering passwords or payment details."
        )
        security_analysis = [
            f"The registered domain {rep['domain']} is among the most visited "
            f"websites worldwide (Tranco rank #{rep['rank']:,}).",
            "Login, account and payment pages of real services often have "
            "address patterns similar to phishing pages, so a URL-pattern "
            "score alone is not treated as proof for an established domain.",
        ]
        if lures:
            why_detected = [lure_reason] + why_detected[:2]
            plain += " " + lure_sentence
            security_analysis.append(lure_sentence)
        if rep.get("shared"):
            # SharePoint, Google Docs / Drive, ... (reputation.py
            # DOCUMENT_SERVICES): genuine service, content by anyone.
            plain += (
                " Anyone can share documents or pages on this service, so also "
                "check who shared the link."
            )
            security_analysis.append(
                "Anyone can publish documents or pages on this service, so the "
                "service being genuine does not prove the content is."
            )
    elif uncertain_brand and verdict["lookalike"]:
        # A misspelling of a brand name (brands.lookalike_brand) on a domain
        # that is not well established.
        brand_name, imitation = verdict["brand"], verdict["lookalike"]
        why_detected = [
            f"The address contains \"{imitation}\", which differs from the brand name "
            f"\"{brand_name}\" by one letter, on a domain that is not one of "
            f"{brand_name}'s well-established websites.",
            "Misspelled brand names (typosquatting) are a common way to make a fake "
            "website look genuine, so this is treated as a caution flag.",
        ]
        evidence = build_evidence("phishing", features, shap_out, lime_out, limit=3)
        plain = (
            f"Suspicious. This address contains \"{imitation}\", a near-spelling of "
            f"\"{brand_name}\", on a domain that is not an established {brand_name} "
            f"website. Open {brand_name} through its official website before entering "
            "passwords or payment details."
        )
        security_analysis = [
            f"\"{imitation}\" is one letter away from \"{brand_name}\", a pattern used by "
            "typosquatting websites.",
            "The URL pattern alone was not enough for a warning, and the misspelled brand "
            "name is what raised this result to suspicious.",
        ]
    elif uncertain_brand:
        # The model scored the URL as legitimate-looking, but the hostname
        # uses a brand that phishers target, on a domain that is not the
        # brand's (not well established) - brands.py rule.
        brand_name = verdict["brand"]
        why_detected = [
            f"The address uses the brand name \"{brand_name}\", but the domain is not "
            f"one of {brand_name}'s well-established websites.",
            f"{brand_name} is one of the brands most often impersonated in recent "
            "phishing campaigns, so a brand name on an unknown domain is treated "
            "as a caution flag.",
        ]
        evidence = build_evidence("phishing", features, shap_out, lime_out, limit=3)
        plain = (
            f"Suspicious. This address uses the brand name \"{brand_name}\" on a domain "
            f"that is not an established {brand_name} website. It may be an official "
            "regional or partner site, or an impersonation - check that you reached "
            f"{brand_name} through its official website before entering passwords or "
            "payment details."
        )
        security_analysis = [
            f"The domain contains \"{brand_name}\" but is not among the most visited "
            "websites, which is where a brand's own sites normally rank.",
            "The URL pattern alone was not enough for a warning, and the brand name on "
            "an unknown domain is what raised this result to suspicious.",
        ]
    elif verdict["escalated_by"] == "brand_impersonation" and verdict["lookalike"]:
        # A look-alike spelling of a brand raised the verdict to phishing
        # (brands.lookalike_brand). The attack analysis names the
        # typosquatting technique; lead with the imitation itself.
        brand_name, imitation = verdict["brand"], verdict["lookalike"]
        # No "the model's decision was reinforced by..." sentence: the
        # model's own score was below the Phishing threshold here.
        why_detected = [
            f"The address imitates the brand name \"{brand_name}\" with the look-alike "
            f"spelling \"{imitation}\", on a domain that is not one of {brand_name}'s "
            "websites.",
        ] + _technique_summary_bullets(attack_analysis, limit=2) + [
            f"The URL pattern score alone is {p_phish:.0%}, and the look-alike brand name "
            "is what raised the verdict to phishing.",
        ]
        evidence = build_evidence(prediction, features, shap_out, lime_out, limit=3)
        plain = (
            f"Phishing. This address imitates \"{brand_name}\" with the look-alike "
            f"spelling \"{imitation}\", a typosquatting trick used to make a fake "
            "website look genuine. Do not enter passwords or payment details."
        )
        security_analysis = None
    elif uncertain_borderline:
        # Score between the tuned "uncertain" and "phishing" thresholds:
        # some phishing-like signals, but not enough for a hard verdict.
        why_detected = build_reason_bullets(
            "phishing", features, shap_out, attack_analysis=None, limit=3,
        )
        evidence = build_evidence("phishing", features, shap_out, lime_out, limit=3)
        plain = (
            f"Suspicious (low-confidence result, {final_score:.0%} score). "
            "Some URL characteristics resemble phishing, but not strongly "
            "enough to confirm it. This is not a confirmed phishing detection - "
            "check the domain name carefully before entering passwords or "
            "payment details."
        )
        security_analysis = [
            "The model's phishing score for this URL falls in the borderline "
            "range: above what is treated as safe, below the confidence needed "
            "for a phishing verdict.",
            "Low-confidence results are shown as suspicious instead of "
            "phishing to avoid falsely accusing legitimate websites.",
        ]
        if lures:
            why_detected = [lure_reason] + why_detected[:2]
            plain += " " + lure_sentence
            security_analysis.append(lure_sentence)
    elif uncertain_https:
        # build_reason_bullets/build_evidence/plain_text_explanation only
        # know "phishing" vs. "legitimate" wording -- "uncertain" gets its
        # own bespoke text here instead of falling into their legitimate-ish
        # else-branch, which would read as a false all-clear.
        why_detected = [
            "The model's own top-weighted signal for this URL is the absence "
            "of a secure HTTPS connection, not a confirmed phishing pattern.",
            "Testing the same URL as if it were served over HTTPS flips the "
            "model's verdict to legitimate, meaning the missing-HTTPS signal "
            "alone is driving the phishing call.",
            "Missing HTTPS is a real risk factor genuine phishing sites often "
            "share, but many legitimate (often older or informational) sites "
            "still don't use it, so this alone isn't treated as proof.",
        ]
        evidence = build_evidence("phishing", features, shap_out, lime_out, limit=3)
        plain = (
            "Suspicious (low-confidence result). The model's score is driven "
            "mainly by the lack of an HTTPS connection, which "
            "is a real but not conclusive risk signal. This is not a confirmed "
            "phishing detection - check the domain name carefully before "
            "entering passwords or payment details."
        )
        security_analysis = [
            "The model's phishing call for this URL is driven almost entirely "
            "by the missing HTTPS connection, not by other structural red flags.",
            "This is shown as suspicious rather than a confirmed phishing "
            "result, since many legitimate sites still don't use HTTPS.",
        ]
    elif verdict["uncertain_reason"] == "short_link":
        # A link shortener hides the destination (ml_state short-link rule).
        host = urlparse(url).hostname
        why_detected = [
            f"{host} is a link-shortening service: the address only forwards to "
            "another website, and that website is not visible in the link.",
            "The URL pattern score describes the short link itself, not the website "
            "it opens, so it cannot show whether that website is safe.",
            "Phishing messages often use short links to hide a fake login page, so "
            "a short link is treated as a caution flag.",
        ]
        evidence = build_evidence("phishing", features, shap_out, lime_out, limit=3)
        plain = (
            f"Suspicious. This is a short link ({host}), so the address does not show "
            "which website it opens. Open it only if you trust who sent it, and check "
            "the address of the page it opens before entering passwords or payment "
            "details."
        )
        security_analysis = [
            "Short links hide their destination, so the website they open cannot be "
            "judged from the link text.",
            "Check the address bar of the page the link opens before entering any "
            "details.",
        ]
    elif verdict["legit_reason"] == "reputable_site":
        # Long or deep address on a well-established domain whose homepage
        # scores as legitimate, with no lure in the address (ml_state
        # reputable-site rule).
        rep = verdict["reputation"]
        raised = [
            _feature_clause(d["feature"], "phishing", features.get(d["feature"]))
            for d in shap_out if d["shap_value"] > 0
        ][:3]
        why_detected = [
            f"The registered domain {rep['domain']} is a well-established website "
            f"(Tranco rank #{rep['rank']:,}), and the model does not flag its homepage "
            f"({homepage_score(rep['domain']):.0%} phishing score, below the "
            f"{UNCERTAIN_THRESHOLD:.0%} warning level).",
            f"The URL pattern score ({p_phish:.1%}) comes from "
            f"{_english_join(raised) if raised else 'the length and structure of the address'}"
            ". Here these come from the site's own subdomain, folder path or document ID: "
            "real document, search and article links on large websites look like "
            "this, so they are not treated as phishing evidence on an established "
            "domain.",
            "The address has none of the lures a phishing page on a shared or hacked "
            "website relies on: no login or payment wording, no other company's brand "
            "name, no link to another website and no user@ prefix.",
        ]
        why_detected = build_reason_bullets("legitimate", features, shap_out, limit=1) + why_detected
        evidence = build_evidence("legitimate", features, shap_out, lime_out, limit=3)
        plain = (
            f"Legitimate. This address belongs to {rep['domain']}, a well-established "
            "website. Its length and structure resemble phishing to the URL-pattern "
            f"model ({p_phish:.1%}), but those parts are chosen by the site itself and "
            "the address carries no phishing lure."
        )
        security_analysis = [
            f"{rep['domain']} is a well-established website (Tranco rank "
            f"#{rep['rank']:,}), and the model does not flag its homepage.",
            "No phishing lure was found in the subdomain, path or query: no login or "
            "payment wording, no other company's brand name, no link to another "
            "website and no user@ prefix.",
        ]
        if rep.get("shared"):
            plain += (
                " Anyone can share files on this service, so check who sent the link "
                "before signing in or downloading anything."
            )
            security_analysis.append(
                "Anyone can share files on this service, so the service being genuine "
                "does not prove the shared content is - check who sent the link."
            )
    elif verdict["legit_reason"] == "http_reputable":
        # Plain-http page on a well-established domain whose only warning
        # signal was the missing HTTPS (ml_state.classify_vec HTTP rule).
        rep = verdict["reputation"]
        why_detected = [
            f"The registered domain {rep['domain']} is a well-established website "
            f"(Tranco rank #{rep['rank']:,}).",
            "The only warning signal for this URL is the missing HTTPS connection: "
            "the same address served over HTTPS scores as legitimate.",
        ]
        # Show the missing-HTTPS signal the text refers to, then the
        # strongest legitimate signals.
        https_card = [
            e for e in build_evidence("phishing", features, shap_out, lime_out, limit=len(shap_out))
            if e["feature"] == "IsHTTPS"
        ]
        evidence = https_card + build_evidence("legitimate", features, shap_out, lime_out, limit=3 - len(https_card))
        plain = (
            f"Legitimate. This page belongs to {rep['domain']}, a well-established "
            "website, and shows no phishing pattern other than using plain HTTP. "
            "The connection is not encrypted, so avoid entering passwords or "
            "payment details unless the page switches to https://."
        )
        security_analysis = [
            "No phishing indicators were found apart from the missing HTTPS connection.",
            "HTTP pages are not encrypted: data you type can be read in transit.",
        ]
    else:
        why_detected = build_reason_bullets(
            prediction,
            features,
            shap_out,
            attack_analysis=attack_analysis,
            limit=4,
        )
        evidence = build_evidence(
            prediction,
            features,
            shap_out,
            lime_out,
            limit=3,
        )
        plain = plain_text_explanation(prediction, risk, shap_out)

        security_analysis = None
        if prediction == "legitimate":
            security_analysis = [
                "No significant phishing indicators were detected by the ML model.",
                "The URL structure matches characteristics commonly associated with legitimate websites.",
            ]

    # Fixed order for the "Why" text: the model and rule reasons first, then
    # the domain age, then the live page check.
    page_lines = [line for line in why_detected if line.startswith("Live page check")]
    why_detected = [line for line in why_detected if line not in page_lines]
    # Every explanation keeps the URL model's own view (its SHAP signals):
    # rule-decided results and long technique lists used to leave it out.
    model_lines = [line for line in why_detected if any(m in line for m in MODEL_LINE_MARKERS)]
    if not model_lines:
        model_lines = [model_signal_line(features, shap_out, p_phish, UNCERTAIN_THRESHOLD,
                                         verdict["score"]["source"] == "rule")]
        why_detected = why_detected[:2] + model_lines
    elif model_lines[0] not in why_detected[:3]:
        why_detected = why_detected[:2] + model_lines[:1]
    why_detected = why_detected[:3]
    age_line = _age_line(verdict, url, prediction)
    if age_line:
        why_detected.append(age_line)
    if not page_lines:
        page_lines = _page_lines(page, prediction)
    why_detected += page_lines[:2]

    if checked_url:
        why_detected = redirect_note + why_detected
        plain = redirect_note[0] + " " + plain

    return {
        "url": req.url,
        "checked_url": checked_url,
        "unicode_host": result["unicode_host"],
        "prediction": prediction,
        "risk_level": risk,
        "confidence": round(verdict["confidence"], 4),
        "uncertain_reason": verdict["uncertain_reason"],
        "legit_reason": verdict["legit_reason"],
        "escalated_by": verdict["escalated_by"],
        "brand": verdict["brand"],
        "lookalike": verdict["lookalike"],
        "lures": lures,
        "page_check": page,
        "stage2": verdict["stage2"],
        "reputation": verdict["reputation"],
        "score": verdict["score"],
        "phishing_probability": round(p_phish, 4),
        "legitimate_probability": round(1 - p_phish, 4),
        "model_used": model_info()["name"],
        "trusted_domain": False,
        "plain_text": plain,
        "attack_analysis": attack_analysis,
        "security_analysis": security_analysis,
        "why_detected": why_detected,
        "evidence": evidence,
        # Raw values are retained for analytics/backward compatibility, but
        # the redesigned Scanner.jsx displays only the compact evidence list.
        "shap": {
            "note": "Positive values push toward PHISHING; negative toward LEGITIMATE.",
            "top_features": shap_out,
            "base_value": round(shap_base, 4),
            "model_score": round(float(MODEL.predict_proba(vec)[0][1]), 4),
            "feature_values": {d["feature"]: features.get(d["feature"]) for d in shap_out},
        },
        "what_if": what_if,
        "lime": {
            "note": "Positive weights support PHISHING; negative support LEGITIMATE.",
            "top_rules": lime_out,
        },
    }


# ---------------------------------------------------------------------------
# Personal history + dashboard
# ---------------------------------------------------------------------------
def _date_range_bounds(date_from: Optional[str], date_to: Optional[str]):
    """Parse YYYY-MM-DD query params into inclusive-day datetime bounds."""
    start = end = None
    if date_from:
        try:
            start = datetime.combine(date.fromisoformat(date_from), time.min)
        except ValueError:
            raise HTTPException(400, "Invalid date_from (expected YYYY-MM-DD)")
    if date_to:
        try:
            end = datetime.combine(date.fromisoformat(date_to), time.max)
        except ValueError:
            raise HTTPException(400, "Invalid date_to (expected YYYY-MM-DD)")
    return start, end


@router.get("/api/detections")
def my_detections(
    page: int = 1,
    page_size: int = 20,
    q: Optional[str] = None,
    result: Optional[str] = None,          # "phishing" | "uncertain" | "legitimate"
    risk: Optional[str] = None,            # "Low" | "Medium" | "High"
    attack_type: Optional[str] = None,
    date_from: Optional[str] = None,       # "YYYY-MM-DD"
    date_to: Optional[str] = None,
    source: Optional[str] = None,          # "website" | "extension"
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = db.query(Detection).filter(Detection.user_id == user.id)
    if q:
        query = query.filter(Detection.url.ilike(f"%{q}%"))
    if result in ("phishing", "uncertain", "legitimate"):
        query = query.filter(Detection.prediction == result)
    if risk in ("Low", "Medium", "High"):
        query = query.filter(Detection.risk_level == risk)
    if attack_type:
        query = query.filter(Detection.attack_type == attack_type)
    if source in ("website", "extension"):
        query = query.filter(Detection.source == source)

    start, end = _date_range_bounds(date_from, date_to)
    if start:
        query = query.filter(Detection.created_at >= start)
    if end:
        query = query.filter(Detection.created_at <= end)

    total = query.count()
    rows = (
        query.order_by(desc(Detection.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "items": [DetectionOut.model_validate(r).model_dump(mode="json") for r in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@router.get("/api/detections/history-summary")
def detections_history_summary(
    source: Optional[str] = None,          # "website" | "extension"
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """
    Feeds the Browser Extension Detection History section: stat cards,
    a 7-day trend, and attack-category / risk-level breakdowns, optionally
    scoped to one source so the page can filter All / Website / Extension.
    """
    q = db.query(Detection).filter(Detection.user_id == user.id)
    if source in ("website", "extension"):
        q = q.filter(Detection.source == source)

    # Counted by the verdict users were shown, not the model's raw label.
    counts = verdict_counts(p for (p,) in q.with_entities(Detection.prediction))
    total = sum(counts.values())
    phishing, suspicious, legitimate = counts["phishing"], counts["suspicious"], counts["legitimate"]
    high_risk = q.filter(Detection.risk_level == "High").count()

    since7 = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=7)
    trend_query = (
        db.query(
            func.date(Detection.created_at).label("day"),
            func.sum((Detection.prediction == "phishing").cast(Integer)).label("phishing"),
            func.sum((Detection.prediction == "uncertain").cast(Integer)).label("suspicious"),
            func.sum((Detection.prediction == "legitimate").cast(Integer)).label("legitimate"),
        )
        .filter(Detection.user_id == user.id, Detection.created_at >= since7)
    )
    if source in ("website", "extension"):
        trend_query = trend_query.filter(Detection.source == source)
    trend_rows = trend_query.group_by("day").order_by("day").all()
    trend_7d = [
        {"day": r.day, "phishing": int(r.phishing or 0),
         "suspicious": int(r.suspicious or 0), "legitimate": int(r.legitimate or 0)}
        for r in trend_rows
    ]

    attack_query = (
        db.query(Detection.attack_type, func.count(Detection.id).label("n"))
        .filter(Detection.user_id == user.id, Detection.attack_type.isnot(None))
    )
    if source in ("website", "extension"):
        attack_query = attack_query.filter(Detection.source == source)
    attack_rows = attack_query.group_by(Detection.attack_type).order_by(desc("n")).all()
    attack_category_frequency = [
        {"category": r[0], "count": int(r[1])} for r in attack_rows
    ]

    risk_query = (
        db.query(Detection.risk_level, func.count(Detection.id).label("n"))
        .filter(Detection.user_id == user.id)
    )
    if source in ("website", "extension"):
        risk_query = risk_query.filter(Detection.source == source)
    risk_counts = {r[0]: int(r[1]) for r in risk_query.group_by(Detection.risk_level).all()}

    return {
        "totals": {
            "total": total, "phishing": phishing, "suspicious": suspicious,
            "legitimate": legitimate, "high_risk": high_risk,
        },
        "trend_7d": trend_7d,
        "attack_category_frequency": attack_category_frequency,
        "risk_distribution": {
            "Low": risk_counts.get("Low", 0),
            "Medium": risk_counts.get("Medium", 0),
            "High": risk_counts.get("High", 0),
        },
    }


_SOURCE_DISPLAY = [
    ("website", "Website Scanner"),
    ("extension", "Chrome Extension"),
]


def _resolve_window(days: int, date_from: Optional[str], date_to: Optional[str]):
    """Shared by the admin and user dashboard-visuals endpoints: resolves the
    (since, until) datetime window from either an explicit start/end date
    range or a day-count fallback."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if date_from and date_to:
        try:
            since = datetime.strptime(date_from, "%Y-%m-%d")
            until = datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1)
            return since, until
        except ValueError:
            pass
    days = max(1, min(days, 90))
    return now - timedelta(days=days), now


def _feature_distribution(urls: List[str]) -> dict:
    """Shared with the admin dashboard's 'Important URL Characteristics'
    chart - counts how many of the given URLs exhibit each characteristic."""
    dist = {
        "long_url": 0, "https": 0, "ip_domain": 0,
        "suspicious_keywords": 0, "many_subdomains": 0,
    }
    suspicious_words = ("login", "verify", "secure", "account", "update",
                         "bank", "confirm", "signin", "password", "billing")
    for url in urls:
        f = extract_features(url)
        if f["URLLength"] > 75:
            dist["long_url"] += 1
        if f["IsHTTPS"] == 1:
            dist["https"] += 1
        if f["IsDomainIP"] == 1:
            dist["ip_domain"] += 1
        if any(w in url.lower() for w in suspicious_words):
            dist["suspicious_keywords"] += 1
        if f["NoOfSubDomain"] >= 3:
            dist["many_subdomains"] += 1
    return dist


def _source_distribution(sources: List[str]) -> list:
    """Shared with the admin dashboard's 'Detection Source Distribution'
    chart - percentage breakdown of where a set of detections came from."""
    total = len(sources)
    counts = Counter(sources)
    return [
        {
            "source": label,
            "count": counts.get(key, 0),
            "percentage": round(counts.get(key, 0) / total * 100, 1) if total else 0.0,
        }
        for key, label in _SOURCE_DISPLAY
    ]


@router.get("/api/detections/dashboard-visuals")
def detections_dashboard_visuals(
    days: int = 14,
    date_from: Optional[str] = None,       # "YYYY-MM-DD", overrides `days` with `date_to`
    date_to: Optional[str] = None,         # "YYYY-MM-DD"
    source: Optional[str] = None,          # "website" | "extension"
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """
    Feeds the interactive chart section of the User Dashboard (Threat Trend,
    Detection Result Overview, Important URL Characteristics, Attack Category
    Analysis, Detection Source Distribution) - same shape as the admin
    dashboard's 'visuals' block, scoped to this user and filterable by time
    window / source. Kept separate from /detections/summary (lifetime KPI
    cards) and /detections/history-summary (Browser Extension History page)
    so neither of those is affected by this filtering.
    """
    since, until = _resolve_window(days, date_from, date_to)

    q = db.query(Detection).filter(
        Detection.user_id == user.id,
        Detection.created_at >= since, Detection.created_at < until,
    )
    if source in ("website", "extension"):
        q = q.filter(Detection.source == source)
    rows = q.all()

    # Counted by the verdict users were shown, not the model's raw label.
    counts = verdict_counts(r.prediction for r in rows)
    phishing, suspicious, legitimate = counts["phishing"], counts["suspicious"], counts["legitimate"]

    trend_map = {}
    for r in rows:
        day = r.created_at.date().isoformat()
        bucket = trend_map.setdefault(day, {"phishing": 0, "suspicious": 0, "legitimate": 0})
        bucket[VERDICT_KEY.get(r.prediction, "legitimate")] += 1
    trend = [
        {"day": day, **counts} for day, counts in sorted(trend_map.items())
    ]

    attack_counts = Counter(r.attack_type for r in rows if r.attack_type)
    attack_category_frequency = [
        {"category": category, "count": count}
        for category, count in attack_counts.most_common()
    ]

    # Source distribution ignores the `source` filter itself (that's the
    # whole point of this chart), but still respects the time window.
    since_rows = (
        db.query(Detection.source)
        .filter(
            Detection.user_id == user.id,
            Detection.created_at >= since, Detection.created_at < until,
        )
        .all()
    )

    return {
        "date_from": since.date().isoformat(),
        "date_to": (until - timedelta(days=1)).date().isoformat(),
        "trend": trend,
        "result_counts": {"phishing": phishing, "suspicious": suspicious, "legitimate": legitimate},
        "feature_distribution": _feature_distribution([r.url for r in rows]),
        "attack_category_frequency": attack_category_frequency,
        "source_distribution": _source_distribution([s for (s,) in since_rows]),
    }


@router.get("/api/detections/summary")
def personal_summary(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """
    Feeds the User Dashboard: totals, feature-distribution counts,
    and a small window of recent scans.
    """
    q = db.query(Detection).filter(Detection.user_id == user.id)
    # Counted by the verdict users were shown, not the model's raw label.
    counts = verdict_counts(p for (p,) in q.with_entities(Detection.prediction))
    total = sum(counts.values())
    phish, suspicious, legit = counts["phishing"], counts["suspicious"], counts["legitimate"]

    # Feature-distribution counts across the user's own scans.
    dist = {
        "long_url": 0, "https": 0, "ip_domain": 0,
        "suspicious_keywords": 0, "many_subdomains": 0,
    }
    suspicious_words = ("login", "verify", "secure", "account", "update",
                         "bank", "confirm", "signin", "password", "billing")
    for row in q.all():
        f = extract_features(row.url)
        if f["URLLength"] > 75:
            dist["long_url"] += 1
        if f["IsHTTPS"] == 1:
            dist["https"] += 1
        if f["IsDomainIP"] == 1:
            dist["ip_domain"] += 1
        if any(w in row.url.lower() for w in suspicious_words):
            dist["suspicious_keywords"] += 1
        if f["NoOfSubDomain"] >= 3:
            dist["many_subdomains"] += 1

    recent = (q.order_by(desc(Detection.created_at)).limit(10).all())

    month_start = datetime.now(timezone.utc).replace(
        tzinfo=None, day=1, hour=0, minute=0, second=0, microsecond=0,
    )
    phishing_this_month = q.filter(
        Detection.prediction == "phishing", Detection.created_at >= month_start,
    ).count()

    # Detection trend for the last 7 days (mirrors the admin dashboard's
    # 14-day trend, scoped to this user).
    since7 = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=7)
    trend_rows = (
        db.query(
            func.date(Detection.created_at).label("day"),
            func.sum((Detection.prediction == "phishing").cast(Integer)).label("phishing"),
            func.sum((Detection.prediction == "uncertain").cast(Integer)).label("suspicious"),
            func.sum((Detection.prediction == "legitimate").cast(Integer)).label("legitimate"),
        )
        .filter(Detection.user_id == user.id, Detection.created_at >= since7)
        .group_by("day").order_by("day").all()
    )
    trend_7d = [
        {"day": r.day, "phishing": int(r.phishing or 0),
         "suspicious": int(r.suspicious or 0), "legitimate": int(r.legitimate or 0)}
        for r in trend_rows
    ]

    return {
        "totals": {"total": total, "phishing": phish, "suspicious": suspicious, "legitimate": legit},
        "feature_distribution": dist,
        "recent": [DetectionOut.model_validate(r).model_dump(mode="json")
                   for r in recent],
        "trend_7d": trend_7d,
        "phishing_this_month": phishing_this_month,
    }


@router.get("/api/detections/{detection_id}")
def detection_detail(
    detection_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    row = db.query(Detection).filter(Detection.id == detection_id).first()
    if not row:
        raise HTTPException(404, "Detection not found")
    if row.user_id != user.id and user.role != "admin":
        raise HTTPException(403, "Not permitted")
    return DetectionOut.model_validate(row)

# ---------------------------------------------------------------------------
# Report phishing URL
# ---------------------------------------------------------------------------

@router.post("/api/report-url", response_model=ReportedURLOut)
def report_url(
    req: ReportURLRequest,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    existing = (
        db.query(ReportedURL)
        .filter(ReportedURL.url == req.url)
        .first()
    )

    if existing:
        raise HTTPException(
            409,
            "This URL has already been reported."
        )

    reported = ReportedURL(
        user_id=user.id,
        url=req.url,
        attack_type=req.attack_type,
        detection_reason=req.detection_reason,
    )

    db.add(reported)
    db.commit()
    db.refresh(reported)

    return reported


@router.get("/api/my-reports", response_model=List[ReportedURLOut])
def my_reports(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """The signed-in user's own reported URLs (their side of the same
    ReportedURL table the admin sees, in full, on the Blacklist Database
    page) - so a user can see only what they personally reported."""
    return (
        db.query(ReportedURL)
        .filter(ReportedURL.user_id == user.id)
        .order_by(desc(ReportedURL.created_at))
        .all()
    )

# ---------------------------------------------------------------------------
# Websites the user blocked from the extension ("Block URL")
# ---------------------------------------------------------------------------
@router.get("/api/my-blocked-urls")
def my_blocked_urls(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    rows = (
        db.query(UserBlockedURL)
        .filter(UserBlockedURL.user_id == user.id)
        .order_by(desc(UserBlockedURL.created_at))
        .all()
    )
    return [
        {
            "id": r.id, "url": r.url, "hostname": r.hostname,
            "attack_type": r.attack_type, "risk_level": r.risk_level,
            "created_at": r.created_at,
        }
        for r in rows
    ]


@router.delete("/api/my-blocked-urls/{block_id}", status_code=status.HTTP_204_NO_CONTENT)
def unblock_url(
    block_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    row = (
        db.query(UserBlockedURL)
        .filter(UserBlockedURL.id == block_id, UserBlockedURL.user_id == user.id)
        .first()
    )
    if not row:
        raise HTTPException(404, "Blocked URL not found")
    db.delete(row)
    db.commit()


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------
@router.get("/api/profile", response_model=UserOut)
def get_profile(user: User = Depends(current_user)):
    return user


@router.patch("/api/profile", response_model=UserOut)
def update_profile(
    payload: ProfileUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()
    if payload.email is not None and payload.email.lower() != user.email:
        clash = db.query(User).filter(User.email == payload.email.lower()).first()
        if clash:
            raise HTTPException(409, "Another account already uses that email")
        user.email = payload.email.lower()
    db.commit()
    db.refresh(user)
    return user


@router.post("/api/profile/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: PasswordChange,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    user.password_hash = hash_password(payload.new_password)
    db.commit()
