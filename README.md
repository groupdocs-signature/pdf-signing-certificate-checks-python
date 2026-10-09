# Certificate Checks and Log Levels When Signing PDFs in Python

[![Product Page](https://img.shields.io/badge/Product%20Page-2865E0?style=for-the-badge&logo=appveyor&logoColor=white)](https://github.com/groupdocs-signature/GroupDocs.Signature-Docs)
[![Docs](https://img.shields.io/badge/Docs-2865E0?style=for-the-badge&logo=Hugo&logoColor=white)](https://docs.groupdocs.com/signature/python-net/)
[![Blog](https://img.shields.io/badge/Blog-2865E0?style=for-the-badge&logo=WordPress&logoColor=white)](https://blog.groupdocs.com/categories/groupdocs.signature-product-family/)
[![Free Support](https://img.shields.io/badge/Free%20Support-2865E0?style=for-the-badge&logo=Discourse&logoColor=white)](https://forum.groupdocs.com/c/signature/13)
[![Temporary License](https://img.shields.io/badge/Temporary%20License-2865E0?style=for-the-badge&logo=rocket&logoColor=white)](https://purchase.groupdocs.com/temp-license/100124)

## Overview

Certificate validity checking is a GroupDocs.Signature behaviour for Python that refuses to sign a document when the signing certificate's validity period has ended, or has not started yet. This repository is a runnable sample built around that behaviour and the two changes shipped alongside it in version 26.9: SHA-256 as the default digest for PDF signatures, and a log level that actually filters what the library reports.

One `python digital_signing_options_demo.py` runs all five parts and prints what happened at each step. The audience is anyone signing PDFs from Python in a service rather than by hand - where a certificate expires on a Tuesday afternoon and the only evidence is a log line nobody configured.

## Technology Stack

- **Platform**: Python 3.9 - 3.14, 64-bit
- **Product**: GroupDocs.Signature for Python via .NET 26.10.0
- **Signing dependency**: `groupdocs-signature-net`, which carries its own .NET runtime - no separate install
- **Certificate dependency**: `cryptography` 42 or later, used only to build the throwaway test certificates

## Problem Statement

A signature made with an expired certificate is not a weaker signature - it is one that validators report as invalid. Adobe Acrobat shows a problem banner, automated checkers return false, and the document is worth less than an unsigned one because somebody believes it was approved. The signing call that produced it, meanwhile, reported success.

Hash algorithms carry a similar quiet failure. A PDF signed with a SHA-1 digest is still a PDF with a signature in it, and plenty of code paths accept it, right up to the validator or the auditor that does not. Neither problem announces itself at the point where it is created, which is the point where it is cheap to fix.

The third part of this sample is about seeing any of it at all. Before 26.9, `SignatureSettings.log_level` was accepted and then ignored, so a service that asked for warnings only still received every trace message the library produced - and a service that asked for silence received them too.

## Solution Overview

GroupDocs.Signature 26.9 moves all three decisions to the point of signing. The certificate's validity period is checked before anything is written, so an expired certificate raises `GroupDocsSignatureException` and leaves no output file behind. Overriding that check is possible, deliberate and per-call, through `allow_expired` and `allow_not_yet_valid`, and each override emits a warning rather than passing silently.

- **`hash_algorithm`**: SHA-256 by default for PDF signatures, with SHA-384 and SHA-512 available when a policy asks for a stronger digest
- **`allow_expired` / `allow_not_yet_valid`**: independent per-call overrides, each paired with a warning in the log
- **`log_level`**: a flags value, so `LogLevel.WARNING | LogLevel.ERROR` keeps problems and drops the ten trace messages a signing run emits

Verification changed in the same release and is worth knowing about here: `verify` now checks every PDF digital signature cryptographically, so a document modified after signing comes back invalid rather than merely uncommented.

## Prerequisites

Before running the sample, install Python 3.9 or later on a 64-bit interpreter - `groupdocs-signature-net` ships a bundled .NET runtime and has no 32-bit wheel. Install the two dependencies with `pip install -r requirements.txt`, which pins `groupdocs-signature-net==26.10.0` and `cryptography>=42.0`.

No certificate files are needed. The sample builds its own, which is the point of the next section.

## Getting Started

### Installation

```bash
pip install -r requirements.txt
```

### Configuration

The sample runs unlicensed in evaluation mode, which is enough to see every behaviour it demonstrates. To remove the evaluation limits, replace the placeholder in `apply_license` with the path to your own `.lic` file and run it again; a free temporary licence is available from the badge at the top of this page.

```python
license_path = "REPLACE_WITH_YOUR_LICENSE_PATH"
if os.path.exists(license_path):
    signature.License().set_license(license_path)
```

The existence check means an unedited clone runs rather than crashing on a missing file.

## Repository Structure

```
pdf-signing-certificate-checks-python/
│
├── digital_signing_options_demo.py
├── requirements.txt
├── documents/
│   └── document.pdf
└── Result/
    ├── signed-sha256.pdf
    ├── signed-sha384.pdf
    ├── signed-sha512.pdf
    ├── signed-expired-allowed.pdf
    ├── signed-not-yet-valid-allowed.pdf
    └── signed-log-levels.pdf
```

### File Descriptions

- **digital_signing_options_demo.py** - the whole sample: a logger class, a certificate factory, six signing and verification functions, and a `main` that runs them in order
- **documents/document.pdf** - the single-page input every part signs
- **Result/** - created at run time; the six signed PDFs above are written here, and `not-signed.pdf` is deliberately never created

## Code Implementation

### Implementation: Test certificates, built in memory

Three certificates are needed - valid, expired, and not valid yet - and none of them can be a file in this repository, because a committed private key is a published private key. Python has no standard-library certificate builder, so this is the one place the sample reaches past GroupDocs.Signature.

```python
certificate = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(not_before)
    .not_valid_after(not_after)
    .sign(key, hashes.SHA256()))

return pkcs12.serialize_key_and_certificates(
    name=b"demo", key=key, cert=certificate, cas=None,
    encryption_algorithm=serialization.BestAvailableEncryption(PASSWORD.encode()))
```

#### Technical Details

`create_pfx` returns PKCS#12 bytes that never touch the disk. `main` calls it three times with validity periods relative to the current moment, which is what keeps the sample working a year from now: the expired certificate is always a year stale and the future one is always a year early, whatever today's date is. A real deployment replaces this function with a certificate from its own CA - self-signed certificates sign correctly and are trusted by nobody.

**Output:** three PKCS#12 byte strings, roughly 2.5 KB each.

### Implementation: Signing with a chosen digest

```python
with signature.Signature(source_path) as sign:
    options = DigitalSignOptions()
    options.certificate_stream = io.BytesIO(pfx)
    options.password = PASSWORD
    options.hash_algorithm = algorithm
    options.reason = "Approved"
    options.location = "Head office"

    result = sign.sign(output_path, options)
    return len(result.succeeded)
```

#### Technical Details

The certificate arrives through `certificate_stream` as an `io.BytesIO`, not as a path, which is how the in-memory certificates reach the library. `hash_algorithm` takes a member of `groupdocs.signature.domain.HashAlgorithm`: `AUTO`, `SHA1`, `SHA256`, `SHA384` or `SHA512`. From 26.9 the default is SHA-256 in the `adbe.pkcs7.detached` format current validators expect, where earlier versions wrote SHA-1. A time stamp, if you add one, uses the same digest as the signature.

**Output:** `1`, and a signed PDF of about 711 KB.

### Implementation: Verifying what was written

```python
with signature.Signature(signed_path) as sign:
    result = sign.verify(DigitalVerifyOptions())
    return result.is_valid
```

#### Technical Details

With no criteria set, this asks the narrow question of whether the signatures match the document. Since 26.9 that check is cryptographic, so a PDF altered after signing is reported invalid. Adding `subject_name`, `issuer_name` or `reason` to the options extends the check to who signed and why. Note what a `True` here does not mean: the sample's certificates are self-signed, so every one of these documents verifies here and is still refused by a PDF reader, which asks the separate question of whether the issuer is trusted.

**Output:** `True` for each of the three digests.

### Implementation: The default refusal

```python
options = DigitalSignOptions()
options.certificate_stream = io.BytesIO(expired_pfx)
options.password = PASSWORD

try:
    sign.sign(output_path, options)
    return True
except signature.GroupDocsSignatureException as error:
    print(f"   Rejected: {str(error).splitlines()[0]}")
    return False
```

#### Technical Details

Nothing is signed and no file is written. The exception message names the certificate, the date it expired, its thumbprint, and the property that would allow it - enough for an application to tell an operator to renew the certificate instead of leaving them to guess. Taking only the first line matters in Python: the exception's text continues with the .NET stack trace from behind the binding, which is not something to show a user.

**Output:** `False`, one message, and no `not-signed.pdf` in `Result/`.

### Implementation: Allowing an expired or early certificate

```python
settings = signature.SignatureSettings(ConsoleLogger())
settings.log_level = LogLevel.WARNING | LogLevel.ERROR

with signature.Signature(source_path, settings=settings) as sign:
    options = DigitalSignOptions()
    options.certificate_stream = io.BytesIO(expired_pfx)
    options.password = PASSWORD
    options.allow_expired = True

    result = sign.sign(output_path, options)
    return len(result.succeeded)
```

#### Technical Details

Two details of the Python binding show up in those first two lines. The logger is a constructor argument, because `SignatureSettings.logger` is read-only - assigning to it raises `AttributeError` - while `log_level` is set afterwards as normal. `sign_with_allow_not_yet_valid` is the same shape with `allow_not_yet_valid` instead; the two flags are independent, so a certificate that is both expired and not yet valid needs both. A certificate that is not valid yet usually means the machine's clock is wrong, which is worth checking before overriding anything, because a wrong clock makes every signature that machine produces questionable.

**Output:** `1`, plus one warning naming the certificate and the date.

### Implementation: Measuring the log level

```python
for label, level in levels:
    logger = CollectingLogger()
    settings = signature.SignatureSettings(logger)
    settings.log_level = level

    with signature.Signature(source_path, settings=settings) as sign:
        options = DigitalSignOptions()
        options.certificate_stream = io.BytesIO(expired_pfx)
        options.password = PASSWORD
        options.allow_expired = True
        sign.sign(os.path.join(RESULT, "signed-log-levels.pdf"), options)
```

#### Technical Details

The same signing runs three times under `LogLevel.NONE`, `LogLevel.WARNING | LogLevel.ERROR` and `LogLevel.ALL`, and `CollectingLogger` counts what arrives. Signing with an allowed expired certificate is what makes the levels measurable rather than theoretical: there is exactly one warning to filter, so the counts come out as nothing at all, then one warning, then that warning plus ten traces. Before 26.9 all three rows would have been identical.

**Output:** `0 errors, 0 warnings, 0 traces` / `0, 1, 0` / `0, 1, 10`.

### Does the log level change what my code receives?

No. The level decides which messages reach your logger and nothing else. An expired certificate still raises `GroupDocsSignatureException` under `LogLevel.NONE`, and `allow_expired` still signs under `LogLevel.ALL` - the exception and the return value are unaffected. What changes is whether anyone finds out afterwards, which is why the warning matters more than the counts.

### Wiring the library into your own logging

`CollectingLogger` is a plain Python class, not a subclass of `groupdocs.signature.logging.ILogger`. That base class wraps a native object and its constructor requires a handle the library owns, so subclassing it raises `TypeError`; the binding marshals any object that provides `error`, `warning` and `trace`, which makes duck typing the supported route.

I spent a while trying to subclass `ILogger` before reading the error properly, so it is worth stating plainly: write an ordinary class. One detail to copy - give `error` and `warning` an optional `exception` parameter, because the library does not always pass one, and a logger that requires it breaks on the messages that omit it.

```python
class StdlibLogger:
    def error(self, message, exception=None):
        logging.getLogger("groupdocs").error(message, exc_info=exception)

    def warning(self, message, exception=None):
        logging.getLogger("groupdocs").warning(message)

    def trace(self, message):
        logging.getLogger("groupdocs").debug(message)
```

A `FileLogger` and a `ConsoleLogger` ship with the library for the cases where that is enough.

## Best Practices

- **Let the default refusal stand** in anything that signs on behalf of users; override per call, never globally
- **Log the warning, not just the count** - the message names the certificate and the date, which is the part an operator can act on
- **Check the clock** before allowing a not-yet-valid certificate, since the certificate is usually right and the machine is wrong
- **Keep traces out of production** and switch them on while diagnosing; one signing run produces around ten
- **Verify after signing** in a pipeline, because `verify` is now a cryptographic check and catches a corrupted output before a user does

## Additional Resources

For more about digital signing and certificate handling with GroupDocs.Signature for Python, these pages go further:

* **Sign Documents with a Digital Certificate in Python** - the full `DigitalSignOptions` reference, including appearance, time stamps and PKCS#11 devices: [Read the article →](https://docs.groupdocs.com/signature/python-net/sign-document-with-digital-signature/)

* **Verify Digital Signatures in PDF and Office Documents** - verification criteria beyond the empty options used here, such as subject and issuer matching: [Read the article →](https://docs.groupdocs.com/signature/python-net/verify-digital-signatures-in-the-document/)

* **Digital Signature Verification in Python - A Practical Walkthrough** - the same verification path written up as a tutorial: [Read the article →](https://blog.groupdocs.com/signature/verify-digital-signature-in-documents-using-python/)

* **Certificate Validity, SHA-2 Digests and Log Levels in .NET** - the same three behaviours from the C# side, if your stack spans both: [Read the article →](https://blog.groupdocs.com/signature/certificate-validity-hash-and-logging-net/)

## Keywords

`digital signature`, `certificate validity`, `allow_expired`, `allow_not_yet_valid`, `sha-256`, `hash algorithm`, `log level`, `groupdocs signature`, `python signing`, `pdf signing`, `expired certificate`, `pkcs12`, `self-signed certificate`, `digitalsignoptions`, `signaturesettings`, `ilogger`, `console logger`, `cryptographic verification`, `python via .net`, `26.9`, `adbe.pkcs7.detached`, `certificate stream`

## Support

For technical support, visit:
- [Free Support Forum](https://forum.groupdocs.com/c/signature/13)
- [Product Documentation](https://docs.groupdocs.com/signature/python-net/)
- [Get Temporary License](https://purchase.groupdocs.com/temp-license/100124)
