package kalkan.worker;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

/** Secure DOM parsing, local ID resolution and document placement for XML signatures. */
final class XmlDocument {
    static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    static final String WSU =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    static final String WSSE =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String SOAP12 = "http://www.w3.org/2003/05/soap-envelope";

    private final Document document;
    private final Map<String, Element> ids;

    private XmlDocument(Document document) throws Failure {
        this.document = document;
        this.ids = registerIDs(document);
    }

    static XmlDocument parse(byte[] encoded) throws Exception {
        return new XmlDocument(parseDOM(encoded));
    }

    // Metadata inspection does not resolve references or require an ID registry.
    static Document parseDOM(byte[] encoded) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.setErrorHandler(
                new DefaultHandler() {
                    @Override
                    public void error(SAXParseException error) throws SAXException {
                        throw error;
                    }

                    @Override
                    public void fatalError(SAXParseException error) throws SAXException {
                        throw error;
                    }
                });
        try {
            return builder.parse(new ByteArrayInputStream(encoded));
        } catch (SAXException error) {
            throw new Failure(
                    Failure.INVALID_ARGUMENT,
                    "XML is malformed or contains a forbidden DTD/entity");
        }
    }

    Document dom() {
        return document;
    }

    Element elementByID(String id) {
        return ids.get(id);
    }

    Element signingTarget(String id) throws Failure {
        Element target = id.isEmpty() ? document.getDocumentElement() : ids.get(id);
        if (target == null) {
            throw new Failure(Failure.INVALID_ARGUMENT, "XML signing node ID was not found");
        }
        return target;
    }

    int signatureCount() {
        return document.getElementsByTagNameNS(DS, "Signature").getLength();
    }

    List<Element> signatures() throws Failure {
        return signatures(document);
    }

    static List<Element> signatures(Document document) throws Failure {
        NodeList nodes = document.getElementsByTagNameNS(DS, "Signature");
        if (nodes.getLength() == 0) {
            throw new Failure(Failure.INVALID_ARGUMENT, "XML contains no signature");
        }
        if (nodes.getLength() > 64) {
            throw new Failure(Failure.INVALID_ARGUMENT, "XML contains too many signatures");
        }
        List<Element> signatures = new ArrayList<>();
        for (int index = 0; index < nodes.getLength(); index++) {
            signatures.add((Element) nodes.item(index));
        }
        return signatures;
    }

    byte[] serialize() throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(output));
        return output.toByteArray();
    }

    Element signatureParent(String name, String namespace) throws Failure {
        if (name.isEmpty()) {
            if (!namespace.isEmpty()) {
                throw new Failure(
                        Failure.INVALID_ARGUMENT, "XML parent namespace requires a parent name");
            }
            return document.getDocumentElement();
        }
        List<Element> matches = new ArrayList<>();
        NodeList nodes = document.getElementsByTagName("*");
        for (int index = 0; index < nodes.getLength(); index++) {
            Element element = (Element) nodes.item(index);
            boolean matchesName =
                    name.equals(element.getLocalName()) || name.equals(element.getTagName());
            boolean matchesNamespace =
                    namespace.isEmpty() || namespace.equals(element.getNamespaceURI());
            if (matchesName && matchesNamespace) {
                matches.add(element);
            }
        }
        if (matches.size() != 1) {
            throw new Failure(
                    Failure.INVALID_ARGUMENT,
                    "XML signature parent must match exactly one element");
        }
        return matches.get(0);
    }

    Element securityHeader(Element body, String id) throws Failure {
        Element envelope = document.getDocumentElement();
        String namespace = envelope.getNamespaceURI();
        requireSOAPBody(envelope, body, id);
        Element header = soapHeader(envelope, body);
        List<Element> securityHeaders = children(header, WSSE, "Security");
        if (securityHeaders.size() > 1) {
            throw new Failure(Failure.INVALID_ARGUMENT, "SOAP contains multiple security headers");
        }
        if (!securityHeaders.isEmpty()) {
            return securityHeaders.get(0);
        }
        Element security = document.createElementNS(WSSE, "wsse:Security");
        security.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:wsse", WSSE);
        String prefix = envelope.getPrefix();
        if (prefix == null || prefix.isEmpty()) {
            prefix = "soap";
            security.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:soap", namespace);
        }
        security.setAttributeNS(
                namespace, prefix + ":mustUnderstand", SOAP12.equals(namespace) ? "true" : "1");
        header.appendChild(security);
        return security;
    }

    private static void requireSOAPBody(Element envelope, Element body, String id) throws Failure {
        String namespace = envelope.getNamespaceURI();
        boolean soapEnvelope =
                (SOAP.equals(namespace) || SOAP12.equals(namespace))
                        && envelope.getLocalName().equals("Envelope");
        boolean directBody =
                soapEnvelope
                        && body.getParentNode() == envelope
                        && namespace.equals(body.getNamespaceURI())
                        && body.getLocalName().equals("Body");
        if (!directBody
                || id.isEmpty()
                || !id.equals(body.getAttributeNS(WSU, "Id"))
                || children(envelope, namespace, "Body").size() != 1) {
            throw new Failure(
                    Failure.INVALID_ARGUMENT,
                    "WSSE requires a unique direct SOAP Body with the requested wsu:Id");
        }
    }

    private Element soapHeader(Element envelope, Element body) throws Failure {
        String namespace = envelope.getNamespaceURI();
        List<Element> headers = children(envelope, namespace, "Header");
        if (headers.size() > 1) {
            throw new Failure(Failure.INVALID_ARGUMENT, "SOAP contains multiple headers");
        }
        if (!headers.isEmpty()) {
            return headers.get(0);
        }
        String prefix = envelope.getPrefix();
        String name = prefix == null || prefix.isEmpty() ? "Header" : prefix + ":Header";
        Element header = document.createElementNS(namespace, name);
        envelope.insertBefore(header, body);
        return header;
    }

    static List<Element> children(Element parent, String namespace, String name) {
        List<Element> result = new ArrayList<>();
        for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element element
                    && namespace.equals(node.getNamespaceURI())
                    && name.equals(node.getLocalName())) {
                result.add(element);
            }
        }
        return result;
    }

    static Element one(Element parent, String namespace, String name) throws Failure {
        List<Element> found = children(parent, namespace, name);
        if (found.size() != 1) {
            throw new Failure(Failure.INVALID_ARGUMENT, "XML requires exactly one " + name);
        }
        return found.get(0);
    }

    private static Map<String, Element> registerIDs(Document document) throws Failure {
        Map<String, Element> ids = new HashMap<>();
        NodeList nodes = document.getElementsByTagName("*");
        for (int elementIndex = 0; elementIndex < nodes.getLength(); elementIndex++) {
            Element element = (Element) nodes.item(elementIndex);
            NamedNodeMap attributes = element.getAttributes();
            for (int attributeIndex = 0;
                    attributeIndex < attributes.getLength();
                    attributeIndex++) {
                Attr attribute = (Attr) attributes.item(attributeIndex);
                if (!isIDAttribute(attribute)) {
                    continue;
                }
                String value = attribute.getValue();
                if (!isLocalID(value) || ids.putIfAbsent(value, element) != null) {
                    throw new Failure(
                            Failure.INVALID_ARGUMENT,
                            "XML IDs must be globally unique and use only local fragment name"
                                    + " characters");
                }
                element.setIdAttributeNode(attribute, true);
            }
        }
        return ids;
    }

    private static boolean isIDAttribute(Attr attribute) {
        String namespace = attribute.getNamespaceURI();
        String name = attribute.getLocalName();
        if (namespace == null || namespace.isEmpty()) {
            return name.equals("Id") || name.equals("id") || name.equals("ID");
        }
        return WSU.equals(namespace) && name.equals("Id")
                || XMLConstants.XML_NS_URI.equals(namespace) && name.equals("id");
    }

    private static boolean isLocalID(String value) {
        // Native SDK signatures use numeric Id="1". Permit all NCName continuation
        // characters in every position, excluding escapes, XPointer syntax,
        // whitespace and namespace separators.
        if (value.isEmpty()) {
            return false;
        }
        for (int offset = 0; offset < value.length(); ) {
            int codePoint = value.codePointAt(offset);
            if (!isNameCharacter(codePoint)) {
                return false;
            }
            offset += Character.charCount(codePoint);
        }
        return true;
    }

    private static boolean isNameCharacter(int codePoint) {
        return isNameStart(codePoint)
                || codePoint >= '0' && codePoint <= '9'
                || codePoint == '-'
                || codePoint == '.'
                || codePoint == 0xB7
                || codePoint >= 0x300 && codePoint <= 0x36F
                || codePoint >= 0x203F && codePoint <= 0x2040;
    }

    private static boolean isNameStart(int codePoint) {
        // XML 1.0 Fifth Edition NameStartChar, excluding the NCName colon.
        return codePoint == '_'
                || codePoint >= 'A' && codePoint <= 'Z'
                || codePoint >= 'a' && codePoint <= 'z'
                || codePoint >= 0xC0 && codePoint <= 0xD6
                || codePoint >= 0xD8 && codePoint <= 0xF6
                || codePoint >= 0xF8 && codePoint <= 0x2FF
                || codePoint >= 0x370 && codePoint <= 0x37D
                || codePoint >= 0x37F && codePoint <= 0x1FFF
                || codePoint >= 0x200C && codePoint <= 0x200D
                || codePoint >= 0x2070 && codePoint <= 0x218F
                || codePoint >= 0x2C00 && codePoint <= 0x2FEF
                || codePoint >= 0x3001 && codePoint <= 0xD7FF
                || codePoint >= 0xF900 && codePoint <= 0xFDCF
                || codePoint >= 0xFDF0 && codePoint <= 0xFFFD
                || codePoint >= 0x10000 && codePoint <= 0xEFFFF;
    }
}
