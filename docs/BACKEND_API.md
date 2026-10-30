# ScamShield Backend API

Base URL: `http://127.0.0.1:5000`

## Health
`GET /api/health`

## Model information
`GET /api/model`

## Scam types
`GET /api/scam-types`

## Scam stages
`GET /api/stages`

## Analyze one item
`POST /api/analyze`

JSON:
```json
{
  "content": "Your bank account will be blocked. Send your OTP immediately.",
  "input_type": "message"
}
```

## Analyze multiple items
`POST /api/analyze/batch`

JSON:
```json
{
  "items": [
    {"content": "Send your OTP immediately.", "input_type": "message"},
    {"content": "Meeting is at 5 PM.", "input_type": "message"}
  ]
}
```

Maximum batch size: 20.

## Input limits

- Maximum analysis text: 5,000 characters
- Accepted input types: message, email, conversation, url
- Maximum HTTP request body: 2 MB

## Response design

A normal analysis returns:
- risk percentage and level
- ML scam probability
- risk components
- scam type and ranking
- scam stage and ranking
- rule hits
- red flags
- URL findings
- explanation
- safety recommendation

The risk weights are prototype weights for the Week-3 educational system and are not calibrated fraud probabilities.


## Language analysis
The `result` returned by `/api/analyze` and each item from `/api/analyze/batch` includes `language_analysis` with `language`, `script`, heuristic `confidence`, `method`, `normalization_applied`, `matched_terms`, and `coverage_note`. It also includes `normalized_text_preview` for debugging/demo visibility. Phrase-based normalization is limited and is not a full translation service.
