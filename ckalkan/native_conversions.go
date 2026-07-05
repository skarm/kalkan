package ckalkan

func storeToNativeInt(storage Store) (int, error) {
	value, err := validateNativeUnsignedRange("storage flag", uint64(storage), uint64(maxNativeCInt), "native C int")
	if err != nil {
		return 0, err
	}

	return int(value), nil //nolint:gosec // value is validated against native C int range before conversion.
}

func storeToNativeUnsignedLong(storage Store) (uint64, error) {
	return validateNativeUnsignedRange("storage flag", uint64(storage), maxNativeUnsignedLong, "native unsigned long")
}

func flagsToNativeUnsignedLong(flags Flag) (uint64, error) {
	return validateNativeSignedRange("flag mask", int64(flags), maxNativeUnsignedLong, "native unsigned long")
}

func flagsToNativeInt(flags Flag) (int, error) {
	value, err := validateNativeSignedRange("flag mask", int64(flags), uint64(maxNativeCInt), "native C int")
	if err != nil {
		return 0, err
	}

	return int(value), nil //nolint:gosec // value is validated against native C int range before conversion.
}
