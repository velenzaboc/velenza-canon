package oodevidence

// CloneReceiptV8 detaches every mutable field of an already typed receipt.
// Copying a verified receipt must not give its consumer a write handle into
// the opaque batch proof that retained it.
func CloneReceiptV8(in ReceiptV8) ReceiptV8 {
	out := in
	out.ReceiptRoles = append([]string(nil), in.ReceiptRoles...)
	out.FetchComponentOrdinal = cloneOptional(in.FetchComponentOrdinal)
	out.SourceRepresentationMediaType = cloneOptional(in.SourceRepresentationMediaType)
	out.PermissionExpectedContentHashAlgorithm = cloneOptional(in.PermissionExpectedContentHashAlgorithm)
	out.PermissionExpectedContentHashProfile = cloneOptional(in.PermissionExpectedContentHashProfile)
	out.PermissionExpectedContentHash = cloneOptional(in.PermissionExpectedContentHash)
	out.PermissionExpiresAt = cloneOptional(in.PermissionExpiresAt)
	out.TransportContentEncoding = cloneOptional(in.TransportContentEncoding)
	out.TransportCharset = cloneOptional(in.TransportCharset)
	return out
}

func CloneBatchV8(in BatchV8) BatchV8 {
	out := in
	out.ExpectedComponentCount = cloneOptional(in.ExpectedComponentCount)
	return out
}

func CloneClosureCertificateV8(in ClosureCertificateV8) ClosureCertificateV8 {
	out := in
	if in.Roots != nil {
		out.Roots = make(map[string]ClosureRoot, len(in.Roots))
		for key, value := range in.Roots {
			out.Roots[key] = value
		}
	}
	return out
}

func cloneOptional[T any](in *T) *T {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}
