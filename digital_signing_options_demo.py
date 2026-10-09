# Topic: Digital signing in GroupDocs.Signature 26.9 - certificate validity checks
# (allow_expired, allow_not_yet_valid), SHA-2 digests for PDF signatures, and log levels.
# Uses GroupDocs.Signature for Python via .NET: DigitalSignOptions, DigitalVerifyOptions
# and SignatureSettings with a logger. Test certificates are built in memory with the
# cryptography package, so the sample ships no private key.

import datetime
import io
import os
import sys

import groupdocs.signature as signature
from groupdocs.signature.domain import HashAlgorithm
from groupdocs.signature.logging import ConsoleLogger, LogLevel
from groupdocs.signature.options import DigitalSignOptions, DigitalVerifyOptions

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

DOCS = "documents"
RESULT = "Result"
SOURCE_PDF = os.path.join(DOCS, "document.pdf")
PASSWORD = "1234567890"


def apply_license() -> None:
    # Point this at your .lic file to remove evaluation limits.
    # Get a free temporary licence: https://purchase.groupdocs.com/temporary-license
    license_path = "REPLACE_WITH_YOUR_LICENSE_PATH"
    if os.path.exists(license_path):
        signature.License().set_license(license_path)
        print("[license] applied")
    else:
        print("[license] no licence set - running in evaluation mode")


class CollectingLogger:
    """
    Collects the messages GroupDocs.Signature writes, so they can be counted per level.

    Remarks:
        Fills the role of the .NET ILogger interface, but it is a plain Python class and
        deliberately does not inherit from groupdocs.signature.logging.ILogger: that base
        class wraps a native object and its constructor needs a handle the library owns,
        so subclassing it raises TypeError. The binding marshals any object that has the
        three methods below, so duck typing is the supported route. Pass an instance to
        the SignatureSettings constructor to route the library's messages into your own
        logging system, such as logging, structlog or Sentry, instead of the console.
        Which messages arrive is decided by SignatureSettings.log_level, which takes
        effect since version 26.9.
    """

    def __init__(self) -> None:
        self.errors = 0
        self.warnings = 0
        self.traces = 0
        self.warning_messages: list[str] = []

    def error(self, message: str, exception: Exception = None) -> None:
        """
        Receives an error message and the exception that caused it.

        Remarks:
            GroupDocs.Signature calls this for unrecoverable problems, for example a
            certificate it refuses to sign with or a document it cannot open. It is
            called only when log_level includes LogLevel.ERROR. The exception argument is
            optional because the library does not always have one to pass, so a logger
            that declares it as required will break on the messages that omit it. The log
            level only filters what is logged: it does not change which exceptions reach
            your code, so an error here is still raised at the call site.
        """
        self.errors += 1

    def warning(self, message: str, exception: Exception = None) -> None:
        """
        Receives a warning message.

        Remarks:
            GroupDocs.Signature calls this when an operation succeeds but the result may
            not be what you expect - signing with an expired certificate that
            allow_expired permits is exactly that case, and it is the one warning this
            sample relies on to make the log levels visibly different. It is called only
            when log_level includes LogLevel.WARNING. The message text is kept in
            warning_messages so an application can show it to whoever started the signing.
        """
        self.warnings += 1
        self.warning_messages.append(str(message))

    def trace(self, message: str) -> None:
        """
        Receives a trace message that describes a step of the process.

        Remarks:
            GroupDocs.Signature calls this for each step of an operation: creating the
            Signature instance, opening the document, starting the sign method, saving the
            result. It is called only when log_level includes LogLevel.TRACE, and one
            signing run produces around ten of them, so leave traces out in production to
            keep the log readable. They are the right thing to switch on while diagnosing
            a signing that fails on one machine and works on another.
        """
        self.traces += 1


def create_pfx(subject: str, not_before: datetime.datetime,
               not_after: datetime.datetime) -> bytes:
    """
    Creates a password-protected PKCS#12 certificate that is valid for the given period.

    Remarks:
        Generates a 2048-bit RSA key, builds a self-signed certificate whose validity
        period is exactly not_before..not_after, marks it for digital signature and
        non-repudiation, and serialises key and certificate into PKCS#12 bytes encrypted
        with PASSWORD. The bytes never touch the disk, which is why this sample contains
        no .pfx file: a private key committed to a repository is a private key published.
        Python has no standard-library certificate builder, so this is the one place the
        sample needs a second dependency, cryptography, which GroupDocs.Signature itself
        does not require. Returns the PKCS#12 bytes, ready for
        DigitalSignOptions.certificate_stream. Use certificates from your own CA in
        production - a self-signed certificate signs correctly but no validator trusts it.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])

    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False),
            critical=False)
        .sign(key, hashes.SHA256())
    )

    return pkcs12.serialize_key_and_certificates(
        name=b"demo", key=key, cert=certificate, cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(PASSWORD.encode()))


def sign_with_hash_algorithm(source_path: str, pfx: bytes, algorithm: int,
                             output_path: str) -> int:
    """
    Signs a PDF document with a digital signature that uses the given hash algorithm.

    Remarks:
        Sets hash_algorithm on a DigitalSignOptions that reads the certificate from a
        stream, and calls sign. Since GroupDocs.Signature 26.9, PDF digital signatures use
        SHA-256 by default, in the adbe.pkcs7.detached format that current validators
        expect; earlier versions wrote SHA-1. HashAlgorithm.SHA384 and HashAlgorithm.SHA512
        are available when a policy asks for a stronger digest, and a time stamp, when you
        add one, uses the same digest. HashAlgorithm.SHA1 remains only for legacy
        validators, and HashAlgorithm.AUTO leaves the choice to the library. The
        certificate arrives as an io.BytesIO through certificate_stream rather than as a
        path, which keeps the private key in memory. Writes the signed PDF to output_path
        and returns the number of signatures added.
    """
    with signature.Signature(source_path) as sign:
        options = DigitalSignOptions()
        options.certificate_stream = io.BytesIO(pfx)
        options.password = PASSWORD
        options.hash_algorithm = algorithm
        options.reason = "Approved"
        options.location = "Head office"

        result = sign.sign(output_path, options)
        return len(result.succeeded)


def verify_pdf_signature(signed_path: str) -> bool:
    """
    Checks that the digital signatures of a PDF document are intact.

    Remarks:
        Calls verify with a DigitalVerifyOptions that sets no criteria. Since
        GroupDocs.Signature 26.9, every PDF digital signature is checked
        cryptographically, so a document that was changed after signing is reported as not
        valid; earlier versions only compared the criteria that were given. Set criteria
        such as subject_name, issuer_name or reason to also check who signed and why.
        Note that a valid result means the signature matches the document, not that the
        certificate is trusted - a self-signed certificate like the ones in this sample
        passes here and is still refused by a PDF reader. Returns True when the
        verification succeeds.
    """
    with signature.Signature(signed_path) as sign:
        result = sign.verify(DigitalVerifyOptions())
        return result.is_valid


def sign_with_expired_certificate(source_path: str, expired_pfx: bytes,
                                  output_path: str) -> bool:
    """
    Tries to sign a PDF document with an expired certificate using the default settings.

    Remarks:
        Since GroupDocs.Signature 26.9, sign rejects a certificate whose validity period
        has ended, or has not started, because validators report such a signature as not
        valid. It raises GroupDocsSignatureException, nothing is signed and nothing is
        saved, and the message names the certificate, the date it expired and the property
        that would allow it. Catching it lets an application tell the user to renew the
        certificate instead of producing a document nobody can trust. The exception's text
        continues with the .NET stack trace behind the binding, so the first line is the
        part worth showing a user. Returns False when the signing is rejected.
    """
    with signature.Signature(source_path) as sign:
        options = DigitalSignOptions()
        options.certificate_stream = io.BytesIO(expired_pfx)
        options.password = PASSWORD

        try:
            sign.sign(output_path, options)
            return True
        except signature.GroupDocsSignatureException as error:
            print(f"   Rejected: {str(error).splitlines()[0]}")
            return False


def sign_with_allow_expired(source_path: str, expired_pfx: bytes,
                            output_path: str) -> int:
    """
    Signs a PDF document with an expired certificate by allowing it explicitly.

    Remarks:
        Sets allow_expired to True, which is useful, for example, to test with an old
        certificate. The document is signed, and GroupDocs.Signature writes a warning to
        the logger given to SignatureSettings: here a ConsoleLogger with
        LogLevel.WARNING | LogLevel.ERROR, so only the warning appears and the ten trace
        messages of a signing run do not. Note that the logger is a constructor argument -
        SignatureSettings.logger is read-only in the Python binding, so assigning to it
        raises AttributeError, while log_level can be set afterwards. Validators still
        report the signature as not valid. Writes the signed PDF to output_path and
        returns the number of signatures added.
    """
    settings = signature.SignatureSettings(ConsoleLogger())
    settings.log_level = LogLevel.WARNING | LogLevel.ERROR

    with signature.Signature(source_path, settings=settings) as sign:
        options = DigitalSignOptions()
        options.certificate_stream = io.BytesIO(expired_pfx)
        options.password = PASSWORD
        options.allow_expired = True

        result = sign.sign(output_path, options)
        return len(result.succeeded)


def sign_with_allow_not_yet_valid(source_path: str, future_pfx: bytes,
                                  output_path: str) -> int:
    """
    Signs a PDF document with a certificate whose validity period has not started yet.

    Remarks:
        Sets allow_not_yet_valid to True. A certificate that is not valid yet was usually
        issued for a later date, or the computer's clock is wrong, so check the clock
        before allowing it - a wrong clock makes every signature you produce suspect, not
        just this one. The two properties are independent: allow_expired does not allow a
        certificate that is not valid yet, and a certificate that is both would need both.
        The document is signed and a warning is written to the logger. Writes the signed
        PDF to output_path and returns the number of signatures added.
    """
    settings = signature.SignatureSettings(ConsoleLogger())
    settings.log_level = LogLevel.WARNING | LogLevel.ERROR

    with signature.Signature(source_path, settings=settings) as sign:
        options = DigitalSignOptions()
        options.certificate_stream = io.BytesIO(future_pfx)
        options.password = PASSWORD
        options.allow_not_yet_valid = True

        result = sign.sign(output_path, options)
        return len(result.succeeded)


def compare_log_levels(source_path: str, expired_pfx: bytes) -> int:
    """
    Signs the same document under three log levels and counts the messages of each kind.

    Remarks:
        Uses SignatureSettings.log_level with a custom logger, CollectingLogger. The values
        are flags, so they combine with the | operator: LogLevel.NONE logs nothing,
        LogLevel.WARNING | LogLevel.ERROR keeps problems only, and LogLevel.ALL, the
        default, adds a trace message for each step. Before version 26.9 the level had no
        effect and every message was logged, which is why a service that set a level and
        saw no change was not misreading its own code. Signing with an allowed expired
        certificate produces one warning, which makes the difference between the levels
        visible without having to break anything. Prints the counts per level and returns
        the number of messages logged with LogLevel.NONE, which is zero.
    """
    levels = (
        ("None", LogLevel.NONE),
        ("Warning | Error", LogLevel.WARNING | LogLevel.ERROR),
        ("All", LogLevel.ALL),
    )

    messages_with_none = -1
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

        total = logger.errors + logger.warnings + logger.traces
        print(f"   {label:<16}: {logger.errors} errors, "
              f"{logger.warnings} warnings, {logger.traces} traces")
        if level == LogLevel.NONE:
            messages_with_none = total

    return messages_with_none


def main() -> int:
    os.makedirs(DOCS, exist_ok=True)
    os.makedirs(RESULT, exist_ok=True)
    apply_license()

    if not os.path.exists(SOURCE_PDF):
        print(f"Missing source document: {os.path.abspath(SOURCE_PDF)}", file=sys.stderr)
        return 1

    # Test certificates: valid now, expired last year, and valid only from next year.
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_pfx = create_pfx("Valid Signer", now - datetime.timedelta(days=1),
                           now + datetime.timedelta(days=365))
    expired_pfx = create_pfx("Expired Signer", now - datetime.timedelta(days=730),
                             now - datetime.timedelta(days=365))
    future_pfx = create_pfx("Future Signer", now + datetime.timedelta(days=365),
                            now + datetime.timedelta(days=730))

    failures = 0

    print("1. Hash algorithms")
    algorithms = (("sha256", HashAlgorithm.SHA256), ("sha384", HashAlgorithm.SHA384),
                  ("sha512", HashAlgorithm.SHA512))
    for name, algorithm in algorithms:
        output = os.path.join(RESULT, f"signed-{name}.pdf")
        sign_with_hash_algorithm(SOURCE_PDF, valid_pfx, algorithm, output)
        valid = verify_pdf_signature(output)
        print(f"   {name}: {os.path.basename(output)}, valid: {valid}")
        failures += 0 if valid else 1

    print("2. Expired certificate with the default settings")
    rejected = os.path.join(RESULT, "not-signed.pdf")
    signed_expired = sign_with_expired_certificate(SOURCE_PDF, expired_pfx, rejected)
    failures += 1 if signed_expired else 0

    print("3. Expired certificate with allow_expired")
    allowed = os.path.join(RESULT, "signed-expired-allowed.pdf")
    failures += 0 if sign_with_allow_expired(SOURCE_PDF, expired_pfx, allowed) == 1 else 1

    print("4. Not-yet-valid certificate with allow_not_yet_valid")
    early = os.path.join(RESULT, "signed-not-yet-valid-allowed.pdf")
    applied = sign_with_allow_not_yet_valid(SOURCE_PDF, future_pfx, early)
    failures += 0 if applied == 1 else 1

    print("5. Log levels")
    messages_with_none = compare_log_levels(SOURCE_PDF, expired_pfx)
    failures += 0 if messages_with_none == 0 else 1

    print(f"Results: {os.path.abspath(RESULT)}")
    return 0 if failures == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
