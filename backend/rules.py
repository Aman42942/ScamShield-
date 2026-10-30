RULES = {
    "Urgency / pressure": ["urgent", "immediately", "act now", "right now", "today only", "last warning", "final notice"],
    "Credential request": ["password", "otp", "one time password", "pin", "cvv", "login details", "verification code", "passcode"],
    "Financial request": ["send money", "transfer money", "pay now", "payment", "deposit", "upi", "bank transfer", "gift card", "processing fee"],
    "Threat / intimidation": ["account will be blocked", "account will be suspended", "legal action", "police", "arrest", "fine", "penalty", "disconnect"],
    "Prize / reward": ["you won", "winner", "lottery", "prize", "reward", "claim your money", "free gift"],
    "Impersonation": ["bank", "income tax", "government", "police", "customs", "customer care", "support team", "official", "kyc"],
    "Investment promise": ["guaranteed profit", "guaranteed returns", "double your money", "risk free", "crypto", "forex", "trading profit"],
    "Remote access request": ["remote access", "anydesk", "teamviewer", "screen sharing", "install this software", "let me control your computer"]
}

SCAM_TYPES = {
    "Banking / KYC Phishing": ["bank", "kyc", "debit card", "credit card", "otp", "net banking", "upi"],
    "Investment Scam": ["investment", "crypto", "trading", "profit", "returns", "stock", "forex"],
    "Prize / Lottery Scam": ["lottery", "prize", "winner", "won", "reward", "claim"],
    "Job / Recruitment Scam": ["job", "vacancy", "work from home", "salary", "hiring", "recruitment", "registration fee"],
    "Romance / Relationship Scam": ["love", "relationship", "romance", "boyfriend", "girlfriend", "emergency"],
    "Delivery / Customs Scam": ["parcel", "package", "delivery", "customs", "courier", "shipment"],
    "Tech Support Scam": ["virus", "computer", "technical support", "remote access", "microsoft", "security alert"],
    "Government / Tax Scam": ["income tax", "tax department", "government", "refund", "tax notice"],
    "Loan / Credit Scam": ["loan", "credit", "emi", "loan approval", "processing fee"],
    "Marketplace / Seller Scam": ["seller", "buyer", "marketplace", "advance payment", "product", "shipping"]
}

STAGES = [
    ("Initial Contact", ["hello", "hi", "contact", "message", "offer", "opportunity"]),
    ("Trust Building", ["trusted", "exclusive", "friend", "relationship", "official", "success story"]),
    ("Urgency / Pressure", ["urgent", "immediately", "act now", "expires", "last warning"]),
    ("Credential Harvesting", ["otp", "password", "pin", "cvv", "login", "verification code", "kyc"]),
    ("Payment Request", ["send money", "payment", "transfer", "deposit", "fee", "upi", "gift card", "pay"]),
    ("Transaction / Investment", ["invest", "investment", "crypto", "trading", "profit", "returns"]),
    ("Exit / Recovery Manipulation", ["recover", "refund", "recovery fee", "unlock", "release fee"]),
]
