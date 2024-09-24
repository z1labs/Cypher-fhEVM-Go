package kms

import "os"

// URL of the KMS gRPC endpoint
var KmsEndpointAddr = os.Getenv("KMS_ENDPOINT_ADDR")
