// Package burrow reads secrets from a self-hosted RatelKey Burrow with a machine identity.
//
// A machine gets its identity when it's added from the Burrow's Machines page, which writes it under ~/.burrow. From
// then on:
//
//	client, err := burrow.Open()
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer client.Close()
//
//	key, err := client.GetSecret(ctx, "payments/prod/API_KEY")
//	apiKey, err := key.Value()
//
//	db, err := client.GetSecret(ctx, "payments/prod/DATABASE")
//	creds, err := db.GetFields("username", "password")
//
// Connect takes an explicit identity instead, Enroll enrolls in memory from a machine token's code, and OIDC reads
// secrets from a CI job with no key. Live, LiveEnvironment and LiveCertificate keep values current as they change on
// the Burrow. GetCertificate gets a certificate from a dynamic certificate secret, such as an SSH login, for a key made
// in memory. VerifyWebhook checks a delivery from a Burrow's Signed webhook.
//
// Every Burrow failure is one of the package's error types (*AuthError, *ForbiddenError, *NotFoundError, *ServerError,
// *CertificateError, *TransportError, *IdentityError, *SecretShapeError, *FieldNotFoundError, *WebhookError), matched
// with errors.As. Each carries the Burrow's own reason.
package burrow
