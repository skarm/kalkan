package javakalkan

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/skarm/kalkan/ckalkan"
)

const zipManifestPath = "META-INF/NCAManifest.xml"

type ncaManifest struct {
	XMLName    xml.Name `xml:"NCAManifest"`
	Signatures []struct {
		URI string `xml:"URI,attr"`
	} `xml:"SigReference"`
	Objects []ncaManifestObject `xml:"DataObjectReference"`
}

type ncaManifestObject struct {
	URI    string `xml:"URI,attr"`
	Method struct {
		Algorithm string `xml:"Algorithm,attr"`
	} `xml:"DigestMethod"`
	Digest string `xml:"DigestValue"`
}

func safeZIPName(name string) bool {
	return name != "" && name != "." && !strings.HasPrefix(name, "/") && path.Clean(name) == name &&
		name != ".." && !strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\\:\x00\r\n")
}

func (c *Operation) zipEntries(filename string) (map[string][]byte, error) {
	encoded, err := c.readEvidenceFile(filename)
	if err != nil {
		return nil, err
	}

	reader, err := zip.NewReader(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		return nil, fmt.Errorf("%w: ZIP container: %w", ErrInvalidInput, err)
	}

	if len(reader.File) > 4096 {
		return nil, fmt.Errorf("%w: ZIP has too many entries", ErrInvalidInput)
	}

	if err := validateZIPLocalHeaders(encoded, reader.File); err != nil {
		return nil, err
	}

	entries := make(map[string][]byte, len(reader.File))
	names := make(map[string]bool, len(reader.File))

	var total int64

	for _, file := range reader.File {
		if err := c.ctx.Err(); err != nil {
			return nil, err
		}

		name := strings.TrimSuffix(file.Name, "/")
		if !safeZIPName(name) || names[strings.ToLower(name)] || file.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: unsafe or duplicate ZIP entry", ErrInvalidInput)
		}

		names[strings.ToLower(name)] = true

		if file.FileInfo().IsDir() {
			// Some ZIP readers use the trailing slash, while Go also honors the
			// directory attribute. Never omit a payload that another reader
			// would extract as an unsigned file.
			if !strings.HasSuffix(file.Name, "/") || file.UncompressedSize64 != 0 || file.CRC32 != 0 {
				return nil, fmt.Errorf("%w: inconsistent ZIP directory entry", ErrInvalidInput)
			}

			continue
		}

		if !file.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: ZIP entries must be regular files or empty directories", ErrInvalidInput)
		}

		if file.UncompressedSize64 > uint64(maxEvidenceSize) || int64(file.UncompressedSize64) > c.evidenceLimit()-total {
			return nil, errEvidenceSize
		}

		input, err := file.Open()
		if err != nil {
			return nil, err
		}

		data, readErr := io.ReadAll(io.LimitReader(input, c.evidenceLimit()-total+1))
		closeErr := input.Close()

		if readErr != nil {
			return nil, readErr
		}

		if closeErr != nil {
			return nil, closeErr
		}

		total += int64(len(data))
		if total > c.evidenceLimit() {
			return nil, errEvidenceSize
		}

		entries[file.Name] = data
	}

	return entries, nil
}

// Streaming ZIP readers use local headers, whereas archive/zip uses the central
// directory. Require both views to identify exactly the same files and bytes.
// Prepended executables and unlisted local entries are not signed payloads.
func validateZIPLocalHeaders(encoded []byte, files []*zip.File) error {
	type entry struct {
		file   *zip.File
		offset int64
	}

	ordered := make([]entry, len(files))
	for i, file := range files {
		offset, err := file.DataOffset()
		if err != nil {
			return fmt.Errorf("%w: ZIP local header: %w", ErrInvalidInput, err)
		}

		ordered[i] = entry{file, offset}
	}

	slices.SortFunc(ordered, func(a, b entry) int {
		switch {
		case a.offset < b.offset:
			return -1
		case a.offset > b.offset:
			return 1
		default:
			return 0
		}
	})

	position := int64(0)

	for _, entry := range ordered {
		var err error

		position, err = validateZIPLocalHeader(encoded, entry.file, position, entry.offset)
		if err != nil {
			return err
		}
	}

	expected := uint32(0x02014b50)
	if len(files) == 0 {
		expected = 0x06054b50
	}

	if position > int64(len(encoded))-4 || binary.LittleEndian.Uint32(encoded[position:]) != expected {
		return fmt.Errorf("%w: ZIP contains unlisted entries or unsupported framing", ErrInvalidInput)
	}

	return nil
}

func validateZIPLocalHeader(encoded []byte, file *zip.File, position, expectedOffset int64) (int64, error) {
	u16, u32 := binary.LittleEndian.Uint16, binary.LittleEndian.Uint32
	if position < 0 || position > int64(len(encoded))-30 || u32(encoded[position:]) != 0x04034b50 {
		return 0, fmt.Errorf("%w: missing or unlisted ZIP local entry", ErrInvalidInput)
	}

	header := encoded[position : position+30]
	nameEnd := position + 30 + int64(u16(header[26:]))
	dataOffset := nameEnd + int64(u16(header[28:]))

	if dataOffset != expectedOffset || dataOffset > int64(len(encoded)) ||
		string(encoded[position+30:nameEnd]) != file.Name || u16(header[6:]) != file.Flags || u16(header[8:]) != file.Method {
		return 0, fmt.Errorf("%w: ZIP local and central headers disagree", ErrInvalidInput)
	}

	compressed, uncompressed, err := zipLocalSizes(header, encoded[nameEnd:dataOffset])
	if err != nil {
		return 0, err
	}

	if file.Flags&8 == 0 {
		if u32(header[14:]) != file.CRC32 || compressed != file.CompressedSize64 || uncompressed != file.UncompressedSize64 {
			return 0, fmt.Errorf("%w: ZIP local sizes or checksum disagree", ErrInvalidInput)
		}
	} else if u32(header[14:]) != 0 && u32(header[14:]) != file.CRC32 ||
		compressed != 0 && compressed != file.CompressedSize64 ||
		uncompressed != 0 && uncompressed != file.UncompressedSize64 {
		return 0, fmt.Errorf("%w: ZIP local descriptor metadata disagrees", ErrInvalidInput)
	}

	if file.CompressedSize64 > uint64(maxEvidenceSize) || file.CompressedSize64 > uint64(len(encoded)) {
		return 0, fmt.Errorf("%w: ZIP compressed payload is truncated or excessive", ErrInvalidInput)
	}

	if dataOffset > int64(len(encoded))-int64(file.CompressedSize64) {
		return 0, fmt.Errorf("%w: ZIP compressed payload is truncated", ErrInvalidInput)
	}

	position = dataOffset + int64(file.CompressedSize64)
	if file.Flags&8 != 0 {
		return zipDescriptorEnd(encoded, position, file)
	}

	return position, nil
}

func zipLocalSizes(header, extra []byte) (uint64, uint64, error) {
	u16, u32, u64 := binary.LittleEndian.Uint16, binary.LittleEndian.Uint32, binary.LittleEndian.Uint64
	compressed, uncompressed := uint64(u32(header[18:])), uint64(u32(header[22:]))

	if compressed != 0xffffffff && uncompressed != 0xffffffff {
		return compressed, uncompressed, nil
	}

	for len(extra) >= 4 {
		tag, size := u16(extra), int(u16(extra[2:]))
		extra = extra[4:]

		if size > len(extra) {
			break
		}

		field := extra[:size]
		extra = extra[size:]

		if tag != 1 {
			continue
		}

		if uncompressed == 0xffffffff && len(field) >= 8 {
			uncompressed, field = u64(field), field[8:]
		}

		if compressed == 0xffffffff && len(field) >= 8 {
			compressed = u64(field)
		}

		if compressed == 0xffffffff || uncompressed == 0xffffffff {
			break
		}

		return compressed, uncompressed, nil
	}

	return 0, 0, fmt.Errorf("%w: missing or malformed ZIP64 local sizes", ErrInvalidInput)
}

func zipDescriptorEnd(encoded []byte, position int64, file *zip.File) (int64, error) {
	u32, u64 := binary.LittleEndian.Uint32, binary.LittleEndian.Uint64
	// The native SDK writes 64-bit descriptors even without ZIP64 headers.
	// Validate the entire descriptor and its boundary, including the optional signature.
	for _, prefix := range []int64{0, 4} {
		if prefix != 0 && (position > int64(len(encoded))-4 || u32(encoded[position:]) != 0x08074b50) {
			continue
		}

		for _, width := range []int64{4, 8} {
			start, end := position+prefix, position+prefix+4+2*width
			if end > int64(len(encoded))-4 || u32(encoded[start:]) != file.CRC32 {
				continue
			}

			compressed, uncompressed := uint64(u32(encoded[start+4:])), uint64(u32(encoded[start+8:]))
			if width == 8 {
				compressed, uncompressed = u64(encoded[start+4:]), u64(encoded[start+12:])
			}

			next := u32(encoded[end:])
			if compressed == file.CompressedSize64 && uncompressed == file.UncompressedSize64 && (next == 0x04034b50 || next == 0x02014b50) {
				return end, nil
			}
		}
	}

	return 0, fmt.Errorf("%w: ZIP data descriptor disagrees", ErrInvalidInput)
}

func parseNCAManifest(entries map[string][]byte) (*ncaManifest, error) {
	var manifest ncaManifest

	data := entries[zipManifestPath]
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: ZIP has no NCAManifest.xml", ErrInvalidInput)
	}

	if err := validateNCAManifestXML(data); err != nil {
		return nil, fmt.Errorf("%w: ZIP manifest: %w", ErrInvalidInput, err)
	}

	if err := xml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("%w: ZIP manifest: %w", ErrInvalidInput, err)
	}

	if manifest.XMLName.Space != "" || len(manifest.Signatures) != 1 || len(manifest.Objects) == 0 {
		return nil, unsupported("ZIP manifest requires one CMS reference and signed data entries")
	}

	signature := manifest.Signatures[0].URI
	if !safeZIPName(signature) || !strings.HasPrefix(signature, "META-INF/signature-") || !strings.HasSuffix(signature, ".cms") || len(entries[signature]) == 0 {
		return nil, fmt.Errorf("%w: ZIP signature reference", ErrInvalidInput)
	}

	return &manifest, nil
}

const ncaDataObject = "DataObjectReference"

type ncaXMLFrame struct {
	name     string
	children map[string]int
}

func (f *ncaXMLFrame) addChild(name string) error {
	allowed := f.name == "NCAManifest" && (name == "SigReference" || name == ncaDataObject) ||
		f.name == ncaDataObject && (name == "DigestMethod" || name == "DigestValue")
	if !allowed {
		return errors.New("unexpected manifest element")
	}

	f.children[name]++

	limit := 1
	if name == ncaDataObject {
		limit = 4094
	}

	if f.children[name] > limit {
		return errors.New("duplicate or excessive manifest element")
	}

	return nil
}

func (f ncaXMLFrame) complete() bool {
	switch f.name {
	case "NCAManifest":
		return f.children["SigReference"] == 1 && f.children[ncaDataObject] != 0
	case ncaDataObject:
		return f.children["DigestMethod"] == 1 && f.children["DigestValue"] == 1
	default:
		return true
	}
}

func ncaManifestElement(element xml.StartElement) (ncaXMLFrame, error) {
	var result ncaXMLFrame

	if element.Name.Space != "" {
		return result, errors.New("manifest elements must not use namespaces")
	}

	attribute := ""

	switch element.Name.Local {
	case "SigReference", ncaDataObject:
		attribute = "URI"
	case "DigestMethod":
		attribute = "Algorithm"
	}

	if attribute == "" && len(element.Attr) != 0 || attribute != "" &&
		(len(element.Attr) != 1 || element.Attr[0].Name != (xml.Name{Local: attribute})) {
		return result, errors.New("unexpected, duplicate or missing manifest attribute")
	}

	return ncaXMLFrame{name: element.Name.Local, children: make(map[string]int)}, nil
}

// validateNCAManifestXML rejects unknown elements, namespaces and duplicate
// fields that encoding/xml's struct decoder would ignore or overwrite, so
// consumers agree on the signed payload references.
func validateNCAManifestXML(data []byte) error {
	var stack []ncaXMLFrame

	rootSeen, declarationSeen := false, false
	decoder := xml.NewDecoder(bytes.NewReader(data))

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			if !rootSeen || len(stack) != 0 {
				return errors.New("incomplete manifest")
			}

			return nil
		}

		if err != nil {
			return err
		}

		switch token := token.(type) {
		case xml.StartElement:
			current, err := ncaManifestElement(token)
			if err != nil {
				return err
			}

			if len(stack) == 0 {
				if rootSeen || current.name != "NCAManifest" {
					return errors.New("manifest requires one NCAManifest root")
				}

				rootSeen = true
			} else if err := stack[len(stack)-1].addChild(current.name); err != nil {
				return err
			}

			stack = append(stack, current)
		case xml.EndElement:
			if len(stack) == 0 || !stack[len(stack)-1].complete() {
				return errors.New("missing required manifest element")
			}

			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(bytes.TrimSpace(token)) != 0 && (len(stack) == 0 || stack[len(stack)-1].name != "DigestValue") {
				return errors.New("unexpected manifest text")
			}
		case xml.ProcInst:
			if rootSeen || declarationSeen || token.Target != "xml" {
				return errors.New("unsupported manifest processing instruction")
			}

			declarationSeen = true
		case xml.Directive:
			return errors.New("manifest DTDs and directives are forbidden")
		}
	}
}

func (c *Operation) verifyZIPEntries(entries map[string][]byte, flags ckalkan.Flag) (string, error) {
	manifest, err := parseNCAManifest(entries)
	if err != nil {
		return "", err
	}

	seen := map[string]bool{zipManifestPath: true, manifest.Signatures[0].URI: true}
	for _, object := range manifest.Objects {
		data, exists := entries[object.URI]
		if !safeZIPName(object.URI) || seen[object.URI] || !exists {
			return "", fmt.Errorf("%w: missing or duplicated ZIP payload reference", ErrInvalidInput)
		}

		seen[object.URI] = true

		var algorithm ckalkan.HashAlgorithm

		switch object.Method.Algorithm {
		case "http://www.w3.org/2001/04/xmlenc#sha256":
			algorithm = ckalkan.SHA256
		case "http://www.w3.org/2001/04/xmldsig-more#gost34311":
			algorithm = ckalkan.GOST95
		case "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512":
			algorithm = ckalkan.GOST2015_512
		default:
			return "", unsupported("ZIP digest algorithm")
		}

		expected, err := base64.StdEncoding.DecodeString(strings.TrimSpace(object.Digest))
		if err != nil {
			return "", fmt.Errorf("%w: ZIP digest encoding", ErrInvalidInput)
		}

		actual, err := c.HashData(algorithm, 0, data)
		if err != nil {
			return "", err
		}

		if subtle.ConstantTimeCompare(actual, expected) != 1 {
			return "", &Error{Operation: "VerifyZIP", Code: 3, Message: "ZIP payload digest mismatch"}
		}
	}

	if len(seen) != len(entries) {
		return "", fmt.Errorf("%w: ZIP contains unsigned extra files", ErrInvalidInput)
	}

	result, err := c.VerifyData(ckalkan.VerifyDataRequest{Signature: entries[manifest.Signatures[0].URI], Data: entries[zipManifestPath], Flags: ckalkan.DetachedData | flags&ckalkan.NoCheckCertTime})
	if err != nil {
		return "", err
	}

	return "ZIP payload digests=OK; " + result.VerifyInfo, nil
}

func (c *Operation) ZipConVerify(filename string, flags ckalkan.Flag) (string, error) {
	entries, err := c.zipEntries(filename)
	if err != nil {
		return "", err
	}

	return c.verifyZIPEntries(entries, flags)
}

func (c *Operation) GetCertFromZipFile(filename string, _ ckalkan.Flag, signerID int) ([]byte, error) {
	entries, err := c.zipEntries(filename)
	if err != nil {
		return nil, err
	}

	manifest, err := parseNCAManifest(entries)
	if err != nil {
		return nil, err
	}

	if signerID < 1 || signerID > 2147483647 {
		return nil, fmt.Errorf("%w: ZIP signer index", ErrInvalidInput)
	}

	return c.GetCertFromCMS(entries[manifest.Signatures[0].URI], signerID, ckalkan.InDER)
}

func (c *Operation) ZipConSign(req ckalkan.ZipConSignRequest) error {
	entries, err := c.zipSigningInputs(req.FilePath)
	if err != nil {
		return err
	}

	var (
		manifestBytes, existing []byte
		signaturePath           string
	)

	if entries[zipManifestPath] != nil {
		if _, err := c.verifyZIPEntries(entries, req.Flags); err != nil {
			return err
		}

		manifest, err := parseNCAManifest(entries)
		if err != nil {
			return err
		}

		manifestBytes, signaturePath = entries[zipManifestPath], manifest.Signatures[0].URI
		existing = entries[signaturePath]
	} else {
		manifestBytes, signaturePath, err = c.newZIPManifest(entries)
		if err != nil {
			return err
		}
	}

	signature, err := c.SignData(ckalkan.SignDataRequest{Alias: req.Alias, Data: manifestBytes, Signature: existing, Flags: ckalkan.SignCMS | ckalkan.DetachedData | ckalkan.WithCert | req.Flags&(ckalkan.NoCheckCertTime|ckalkan.WithTimestamp)})
	if err != nil {
		return err
	}

	entries[zipManifestPath], entries[signaturePath] = manifestBytes, signature

	var uncompressedSize int64
	for _, data := range entries {
		uncompressedSize += int64(len(data))
	}

	if uncompressedSize > c.evidenceLimit() {
		return errEvidenceSize
	}

	var encoded bytes.Buffer

	writer := zip.NewWriter(&encoded)
	for _, name := range sortedZIPNames(entries) {
		output, err := writer.Create(name)
		if err != nil {
			return err
		}

		if _, err := output.Write(entries[name]); err != nil {
			return err
		}
	}

	if err := writer.Close(); err != nil {
		return err
	}

	if int64(encoded.Len()) > c.evidenceLimit() {
		return errEvidenceSize
	}

	if err := c.ctx.Err(); err != nil {
		return err
	}

	if filepath.Base(req.Name) != req.Name || req.Name == "." || req.Name == "" {
		return fmt.Errorf("%w: ZIP output name", ErrInvalidInput)
	}

	name := req.Name
	if !strings.HasSuffix(strings.ToLower(name), ".zip") {
		name += ".zip"
	}

	destination := filepath.Join(req.OutDir, name)

	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}

	_, writeErr := file.Write(encoded.Bytes())

	closeErr := file.Close()
	if writeErr == nil {
		writeErr = closeErr
	}

	if writeErr == nil {
		writeErr = c.ctx.Err()
	}

	if writeErr != nil {
		_ = os.Remove(destination)
	}

	return writeErr
}

func sortedZIPNames(entries map[string][]byte) []string {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}

	slices.Sort(names)

	return names
}

func (c *Operation) zipSigningInputs(filename string) (map[string][]byte, error) {
	// The native SDK uses a pipe-terminated list for individual files.
	paths := strings.Split(strings.TrimSuffix(filename, "|"), "|")
	if len(paths) == 1 {
		return c.zipSigningInput(paths[0])
	}

	entries := make(map[string][]byte)
	names := make(map[string]bool)

	var total int64

	for _, filename := range paths {
		info, err := os.Lstat(filename)
		if err != nil {
			return nil, err
		}

		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: ZIP list inputs must be regular files", ErrInvalidInput)
		}

		name := filepath.Base(filename)
		if !safeZIPName(name) || names[strings.ToLower(name)] {
			return nil, fmt.Errorf("%w: unsafe or duplicate ZIP payload name", ErrInvalidInput)
		}

		data, err := c.readEvidenceFile(filename)
		if err != nil {
			return nil, err
		}

		total += int64(len(data))
		if total > c.evidenceLimit() || len(entries) >= 4094 {
			return nil, errEvidenceSize
		}

		names[strings.ToLower(name)] = true
		entries[name] = data
	}

	return entries, nil
}

func (c *Operation) zipSigningInput(filename string) (map[string][]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() && strings.EqualFold(filepath.Ext(filename), ".zip") {
		return c.zipEntries(filename)
	}

	entries := make(map[string][]byte)
	names := make(map[string]bool)

	var total int64

	add := func(file, name string) error {
		if !safeZIPName(name) || names[strings.ToLower(name)] || strings.EqualFold(name, "META-INF") || strings.EqualFold(name, zipManifestPath) || strings.HasPrefix(strings.ToUpper(name), "META-INF/") {
			return fmt.Errorf("%w: reserved or unsafe ZIP payload name", ErrInvalidInput)
		}

		data, err := c.readEvidenceFile(file)
		if err != nil {
			return err
		}

		total += int64(len(data))
		if total > c.evidenceLimit() || len(entries) >= 4094 {
			return errEvidenceSize
		}

		names[strings.ToLower(name)] = true
		entries[name] = data

		return nil
	}

	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: ZIP input must be regular", ErrInvalidInput)
		}

		err = add(filename, filepath.Base(filename))
	} else {
		err = filepath.WalkDir(filename, func(file string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

			if err := c.ctx.Err(); err != nil {
				return err
			}

			if entry.Type()&fs.ModeSymlink != 0 {
				return fmt.Errorf("%w: ZIP symlink inputs are unsupported", ErrInvalidInput)
			}

			if entry.IsDir() {
				return nil
			}

			relative, err := filepath.Rel(filename, file)
			if err != nil {
				return err
			}

			return add(file, filepath.ToSlash(relative))
		})
	}

	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: ZIP has no input files", ErrInvalidInput)
	}

	return entries, nil
}

func (c *Operation) newZIPManifest(entries map[string][]byte) ([]byte, string, error) {
	if len(entries) == 0 || len(entries) > 4094 {
		return nil, "", fmt.Errorf("%w: ZIP needs between 1 and 4094 payload files", ErrInvalidInput)
	}

	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, "", err
	}

	signaturePath := "META-INF/signature-" + hex.EncodeToString(id) + ".cms"
	manifest := ncaManifest{Signatures: []struct {
		URI string `xml:"URI,attr"`
	}{{URI: signaturePath}}}

	for _, name := range sortedZIPNames(entries) {
		if strings.EqualFold(name, "META-INF") || strings.HasPrefix(strings.ToUpper(name), "META-INF/") {
			return nil, "", unsupported("unsigned ZIP contains reserved META-INF files")
		}

		digest, err := c.HashData(ckalkan.SHA256, 0, entries[name])
		if err != nil {
			return nil, "", err
		}

		object := ncaManifestObject{URI: name, Digest: base64.StdEncoding.EncodeToString(digest)}
		object.Method.Algorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
		manifest.Objects = append(manifest.Objects, object)
	}

	encoded, err := xml.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, "", err
	}

	return append([]byte(xml.Header), encoded...), signaturePath, nil
}
