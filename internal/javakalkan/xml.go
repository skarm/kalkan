package javakalkan

import (
	"strconv"

	"github.com/skarm/kalkan/ckalkan"
)

func (c *Operation) SignXML(req ckalkan.SignXMLRequest) ([]byte, error) {
	return c.xmlResult("SignXML", 30, []byte(req.Alias), req.XML, []byte(req.SignNodeID),
		[]byte(req.ParentSignNode), []byte(req.ParentNamespace), xmlFlags(req.Flags), encodeFlag(req.Flags, ckalkan.NoCheckCertTime))
}

func (c *Operation) VerifyXML(alias string, flags ckalkan.Flag, xml []byte) (string, error) {
	result, err := c.xmlResult("VerifyXML", 31, []byte(alias), xml, xmlFlags(flags), encodeFlag(flags, ckalkan.NoCheckCertTime))
	return string(result), err
}

func (c *Operation) SignWSSE(req ckalkan.SignWSSERequest) ([]byte, error) {
	return c.xmlResult("SignWSSE", 32, []byte(req.Alias), req.XML, []byte(req.SignNodeID),
		xmlFlags(req.Flags), encodeFlag(req.Flags, ckalkan.NoCheckCertTime))
}

func (c *Operation) GetCertFromXML(xml []byte, signID int) ([]byte, error) {
	return c.xmlResult("GetCertFromXML", 33, xml, []byte(strconv.Itoa(signID)))
}

func (c *Operation) GetSigAlgFromXML(xml []byte) (string, error) {
	result, err := c.xmlResult("GetSigAlgFromXML", 34, xml)
	return string(result), err
}

func xmlFlags(flags ckalkan.Flag) []byte {
	return []byte(strconv.FormatInt(int64(flags&^ckalkan.NoCheckCertTime), 10))
}

func (c *Operation) xmlResult(operation string, opcode int32, args ...[]byte) ([]byte, error) {
	fields, err := c.call(operation, opcode, 1, args...)
	if err != nil {
		return nil, err
	}

	if err := c.checkOutputSize(operation, len(fields[0])); err != nil {
		return nil, err
	}

	return fields[0], nil
}
