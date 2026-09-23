# Contributing

Contributions should improve correctness, reproducibility, or clarity without
inflating the project's claims.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

## Change requirements

1. Open an issue describing the problem, evidence, and intended scope.
2. Keep each pull request focused on one coherent change.
3. Add or update a test for behavioral changes. Demonstrate that the test fails
   before the implementation and passes afterward.
4. Run the full test and compilation commands from the README.
5. Update the methodology when changing any measured operation, aggregation,
   schema field, or chart.
6. Cite primary sources for cryptographic or standards claims.
7. Do not describe functional tests as a security proof, certification, or
   peer-reviewed result.

## Style

- Prefer small, explicit functions and standard-library tooling.
- Keep cryptographic composition in `crypto_backends.py`, experiment-record
  logic in `experiment.py`, and interface concerns in `main.py`.
- Never invent benchmark values or security scores.
- Do not add custom cryptographic primitives when a reviewed library provides
  the required primitive.

## Pull requests

Include the motivation, commands run, observed output, limitations, and any
change to the threat model. Never include real private keys, secrets, malware,
or sensitive personal data in an issue, fixture, commit, or pull request.
